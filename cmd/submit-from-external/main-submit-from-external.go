package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bgentry/que-go"
	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/jackc/pgx"

	"github.com/govau/certwatch/db"
	"github.com/govau/certwatch/jobs"
	"github.com/govau/cf-common/env"
	"github.com/govau/verifiable-logs/generalisedtransparency"
)

const (
	WorkerCount = 1
)

type resource struct {
	Resource string `json:"resource"`
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

	pgxPool, err := db.GetPGXPool(WorkerCount * 2)
	if err != nil {
		log.Fatal(err)
	}

	baseURL := envLookup.String("CKAN_BASE_URL", "https://data.gov.au")
	resourceIDs := strings.Split(envLookup.String("CKAN_RESOURCE_ID", ""), ",")

	qc := que.NewClient(pgxPool)

	tx, err := pgxPool.Begin()
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Rollback()

	for _, rid := range resourceIDs {
		bb, err := json.Marshal(&resource{
			Resource: rid,
		})
		if err != nil {
			log.Fatal(err)
		}
		err = qc.EnqueueInTx(&que.Job{
			Type:  "fetch_entry_metadata",
			Args:  bb,
			RunAt: time.Now(),
		}, tx)
		if err != nil {
			log.Fatal(err)
		}
	}
	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}

	tableValidator, err := generalisedtransparency.CreateNamedValidator("whitelist", strings.Join(resourceIDs, ","))
	if err != nil {
		log.Fatal(err)
	}

	logSubmitter := &generalisedtransparency.LogSubmitter{
		Server:             envLookup.MustString("VERIFIABLE_LOG_SERVER"),
		APIKey:             envLookup.MustString("VERIFIABLE_LOG_API_KEY"),
		TableNameValidator: tableValidator,
	}

	workers := que.NewWorkerPool(qc, que.WorkMap{
		"fetch_entry_metadata": (&jobs.JobFuncWrapper{
			QC:     qc,
			Logger: log.New(os.Stderr, "", log.LstdFlags),
			F: func(qc *que.Client, logger *log.Logger, job *que.Job, tx *pgx.Tx) error {
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
					"sql": []string{fmt.Sprintf(`SELECT * FROM "%s" WHERE _id > %d ORDER BY _id LIMIT 100`, tName, lastID)},
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

				if len(jsonResp.Result.Records) == 0 {
					return nil
				}

				for _, dataToSubmit := range jsonResp.Result.Records {
					id, err := generalisedtransparency.JSONIntID(dataToSubmit["_id"])
					if err != nil {
						return err
					}

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

					// we're in ASC order
					lastID = id
				}

				_, err = tx.Exec(`UPDATE processed_ids SET last_id = $2 WHERE resource = $1`, tName, lastID)
				if err != nil {
					return err
				}

				return tx.Commit()
			},
			Singleton: true,
			Duration:  time.Minute * 5,
		}).Run,
		"update_sct": (&jobs.JobFuncWrapper{
			QC:     qc,
			Logger: log.New(os.Stderr, "", log.LstdFlags),
			F: func(qc *que.Client, logger *log.Logger, job *que.Job, tx *pgx.Tx) error {
				var jd submitRecord
				err := json.Unmarshal(job.Args, &jd)
				if err != nil {
					return err
				}
				return logSubmitter.SubmitToLogAndUpdateRecord(context.Background(), jd.Table, jd.Data, nil)
			},
		}).Run,
	}, WorkerCount)

	// Prepare a shutdown function
	shutdown := func() {
		workers.Shutdown()
		pgxPool.Close()
	}

	// Normal exit
	defer shutdown()

	// Or via signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	signal.Notify(sigCh, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %v, starting shutdown...", sig)
		shutdown()
		log.Println("Shutdown complete")
		os.Exit(0)
	}()

	go workers.Start()

	log.Println("Started up... waiting for ctrl-C.")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Up and away.")
	})
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", os.Getenv("PORT")), nil))
}
