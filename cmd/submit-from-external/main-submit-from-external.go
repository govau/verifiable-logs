package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bgentry/que-go"
	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/jackc/pgx"

	"github.com/govau/cf-common/env"
	"github.com/govau/cf-common/jobs"
	"github.com/govau/verifiable-logs/generalisedtransparency"
)

type resource struct {
	Resource string `json:"resource"`
}

type fetchEntriesArgs struct {
	Resource string `json:"resource"`

	// Start is inclusive
	Start int `json:"start"`

	// End is inclusive
	End int `json:"end"`
}

type submitRecord struct {
	Table string                 `json:"table"`
	Data  map[string]interface{} `json:"data"`
}

func main() {
	app, err := cfenv.Current()
	if err != nil {
		log.Fatal(err)
	}
	envLookup := env.NewVarSet(
		env.WithOSLookup(), // Always look in the OS env first.
		env.WithUPSLookup(app, "submit-external-ups"),
	)

	baseURL := envLookup.String("CKAN_BASE_URL", "https://data.gov.au")
	resourceIDs := strings.Split(envLookup.String("CKAN_RESOURCE_IDS", ""), ",")

	tableValidator, err := generalisedtransparency.CreateNamedValidator("whitelist", strings.Join(resourceIDs, ","))
	if err != nil {
		log.Fatal(err)
	}

	logSubmitter := &generalisedtransparency.LogSubmitter{
		Server:             envLookup.MustString("VERIFIABLE_LOG_SERVER"),
		APIKey:             envLookup.MustString("VERIFIABLE_LOG_API_KEY"),
		TableNameValidator: tableValidator,
	}

	workerCount, err := strconv.Atoi(envLookup.String("QUE_WORKERS", "2"))
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal((&jobs.Handler{
		PGXConnConfig: jobs.MustPGXConfigFromCloudFoundry(),
		WorkerCount:   workerCount,
		InitSQL: `
			CREATE TABLE IF NOT EXISTS processed_ids (
				resource   text      PRIMARY KEY,
				last_id    bigint    NOT NULL DEFAULT 0
			);
		`,
		OnStart: func(qc *que.Client, pool *pgx.ConnPool, logger *log.Logger) error {
			err := bootstrapJobs(qc, pool, resourceIDs)
			if err != nil {
				return err
			}
			go http.ListenAndServe(fmt.Sprintf(":%s", os.Getenv("PORT")), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "HEALTHY")
			}))
			log.Println("Server up...")
			return nil
		},
		WorkerMap: map[string]*jobs.JobConfig{
			"update_sct": &jobs.JobConfig{
				F: func(qc *que.Client, logger *log.Logger, job *que.Job, tx *pgx.Tx) error {
					var jd submitRecord
					err := json.Unmarshal(job.Args, &jd)
					if err != nil {
						return err
					}
					return logSubmitter.SubmitToLogAndUpdateRecord(context.Background(), jd.Table, jd.Data, nil)
				},
			},

			"fetch_entry_metadata": &jobs.JobConfig{
				F: func(qc *que.Client, logger *log.Logger, job *que.Job, tx *pgx.Tx) error {
					return fetchEntryMetadata(qc, logger, job, tx, tableValidator, baseURL)
				},
				Singleton: true,
				Duration:  time.Minute * 5,
			},

			"fetch_entries": &jobs.JobConfig{
				F: func(qc *que.Client, logger *log.Logger, job *que.Job, tx *pgx.Tx) error {
					return fetchEntries(qc, logger, job, tx, tableValidator, baseURL)
				},
			},
		},
	}).WorkForever())
}

func bootstrapJobs(qc *que.Client, pool *pgx.ConnPool, resourceIDs []string) error {
	tx, err := pool.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, rid := range resourceIDs {
		bb, err := json.Marshal(&resource{
			Resource: rid,
		})
		if err != nil {
			return err
		}
		err = qc.EnqueueInTx(&que.Job{
			Type: "fetch_entry_metadata",
			Args: bb,
		}, tx)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

const (
	maxAtOnce = 100
)

func fetchEntries(qc *que.Client, logger *log.Logger, job *que.Job, tx *pgx.Tx, tableValidator generalisedtransparency.TableNameValidator, baseURL string) error {
	var jd fetchEntriesArgs
	err := json.Unmarshal(job.Args, &jd)
	if err != nil {
		return err
	}

	tName, err := tableValidator.ValidateAndCanonicaliseTableName(jd.Resource)
	if err != nil {
		return err
	}

	desiredEnd := jd.End
	if desiredEnd > (jd.Start + maxAtOnce) {
		desiredEnd = jd.Start + maxAtOnce
	}

	// Schedule more jobs if needed
	if desiredEnd < jd.End {
		midpoint := (jd.End + desiredEnd) / 2

		nextA := &fetchEntriesArgs{Resource: jd.Resource, Start: desiredEnd + 1, End: midpoint}
		if nextA.Start <= nextA.End && nextA.End <= jd.End {
			bb, err := json.Marshal(nextA)
			if err != nil {
				return err
			}
			err = qc.EnqueueInTx(&que.Job{
				Type: "fetch_entries",
				Args: bb,
			}, tx)
			if err != nil {
				return err
			}
		}

		nextB := &fetchEntriesArgs{Resource: jd.Resource, Start: midpoint + 1, End: jd.End}
		if nextB.Start <= nextB.End {
			bb, err := json.Marshal(nextB)
			if err != nil {
				return err
			}
			err = qc.EnqueueInTx(&que.Job{
				Type: "fetch_entries",
				Args: bb,
			}, tx)
			if err != nil {
				return err
			}
		}

	}

	// Go out and search
	resp, err := http.Get(baseURL + "/api/3/action/datastore_search_sql?" + (&url.Values{
		"sql": []string{fmt.Sprintf(`SELECT * FROM "%s" WHERE _id >= %d AND _id <= %d`, tName, jd.Start, desiredEnd)},
	}).Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	var jsonResp struct {
		Result struct {
			Records []map[string]interface{} `json:"records"`
		} `json:"result"`
	}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return err
	}

	for _, dataToSubmit := range jsonResp.Result.Records {
		bb, err := json.Marshal(&submitRecord{
			Table: tName,
			Data:  dataToSubmit,
		})
		if err != nil {
			return err
		}

		err = qc.EnqueueInTx(&que.Job{
			Type: "update_sct",
			Args: bb,
		}, tx)
		if err != nil {
			return err
		}
	}

	// Please commit and save
	return nil
}

func fetchEntryMetadata(qc *que.Client, logger *log.Logger, job *que.Job, tx *pgx.Tx, tableValidator generalisedtransparency.TableNameValidator, baseURL string) error {
	var r resource
	err := json.Unmarshal(job.Args, &r)
	if err != nil {
		return err
	}

	tName, err := tableValidator.ValidateAndCanonicaliseTableName(r.Resource)
	if err != nil {
		return err
	}

	var lastID int
	err = tx.QueryRow(`SELECT last_id FROM processed_ids WHERE resource = $1 FOR UPDATE`, tName).Scan(&lastID)
	switch err {
	case nil:
		// continue
	case pgx.ErrNoRows:
		_, err = tx.Exec("INSERT INTO processed_ids(resource, last_id) VALUES ($1, $2)", tName, 0)
		if err != nil {
			return err
		}
		return jobs.ErrImmediateReschedule
	default:
		return err
	}

	// Go out and search
	resp, err := http.Get(baseURL + "/api/3/action/datastore_search_sql?" + (&url.Values{
		"sql": []string{fmt.Sprintf(`SELECT MAX(_id) AS max_id FROM "%s"`, tName)},
	}).Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	var jsonResp struct {
		Result struct {
			Records []struct {
				ID int `json:"max_id"`
			} `json:"records"`
		} `json:"result"`
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return err
	}

	if len(jsonResp.Result.Records) == 0 {
		return errors.New("unexpectedly got no results fetching max id")
	}

	maxID := jsonResp.Result.Records[0].ID

	if maxID <= lastID {
		// our work here is done
		return nil
	}

	bb, err := json.Marshal(&fetchEntriesArgs{
		Resource: tName,
		Start:    lastID + 1,
		End:      maxID,
	})
	if err != nil {
		return err
	}

	err = qc.EnqueueInTx(&que.Job{
		Type: "fetch_entries",
		Args: bb,
	}, tx)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`UPDATE processed_ids SET last_id = $2 WHERE resource = $1`, tName, maxID)
	if err != nil {
		return err
	}

	// Please commit and save
	return nil
}
