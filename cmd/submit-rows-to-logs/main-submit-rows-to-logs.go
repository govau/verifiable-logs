package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strconv"

	que "github.com/bgentry/que-go"
	"github.com/govau/cf-common/jobs"
	"github.com/govau/verifiable-logs/generalisedtransparency"

	"github.com/jackc/pgx"
)

func main() {
	workerCount, err := strconv.Atoi(os.Getenv("QUE_WORKERS"))
	if err != nil {
		log.Fatal(err)
	}

	config, err := pgx.ParseEnvLibpq()
	if err != nil {
		log.Fatal(err)
	}

	tableValidator, err := generalisedtransparency.CreateNamedValidator(os.Getenv("VERIFIABLE_TABLENAME_VALIDATOR"), os.Getenv("VERIFIABLE_TABLENAME_VALIDATOR_PARAM"))
	if err != nil {
		log.Fatal(err)
	}

	logSubmitter := &generalisedtransparency.LogSubmitter{
		Server:             os.Getenv("VERIFIABLE_LOG_SERVER"),
		APIKey:             os.Getenv("VERIFIABLE_LOG_API_KEY"),
		TableNameValidator: tableValidator,
	}

	log.Fatal((&jobs.Handler{
		PGXConnConfig: &config,
		WorkerCount:   workerCount,
		QueueName:     os.Getenv("QUE_QUEUE"),
		OnStart: func(qc *que.Client, pool *pgx.ConnPool, logger *log.Logger) error {
			logger.Println("Started up... waiting for ctrl-C.")
			return nil
		},
		WorkerMap: map[string]*jobs.JobConfig{
			"update_sct": &jobs.JobConfig{
				F: func(qc *que.Client, logger *log.Logger, job *que.Job, tx *pgx.Tx) error {
					var jd struct {
						Table string                 `json:"table"`
						Data  map[string]interface{} `json:"data"`
					}
					err := json.Unmarshal(job.Args, &jd)
					if err != nil {
						return err
					}
					logger.Printf("updating %s, row %s\n", jd.Table, jd.Data["_id"])
					return logSubmitter.SubmitToLogAndUpdateRecord(context.Background(), jd.Table, jd.Data, job.Conn())
				},
			},
		},
	}).WorkForever())
}
