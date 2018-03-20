package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	que "github.com/bgentry/que-go"
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

	pgxPool, err := pgx.NewConnPool(pgx.ConnPoolConfig{
		MaxConnections: workerCount * 2,
		ConnConfig:     config,
		AfterConnect:   que.PrepareStatements,
	})
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
	qc := que.NewClient(pgxPool)
	workers := que.NewWorkerPool(qc, que.WorkMap{
		"update_sct": func(job *que.Job) error {
			var jd struct {
				Table string                 `json:"table"`
				Data  map[string]interface{} `json:"data"`
			}
			err := json.Unmarshal(job.Args, &jd)
			if err != nil {
				return err
			}
			log.Printf("updating %s, row %s\n", jd.Table, jd.Data["_id"])
			err = logSubmitter.SubmitToLogAndUpdateRecord(context.Background(), jd.Table, jd.Data, job.Conn())
			if err != nil {
				log.Printf("error (will retry): %s", err)
			}
			return err
		},
	}, workerCount)
	workers.Queue = os.Getenv("QUE_QUEUE")

	// Prepare a shutdown function
	shutdown := func() {
		workers.Shutdown()
		pgxPool.Close()
	}

	// Normal exit (which is dead code really, due to the select {} later)
	// but we leave it here anyway as it's a fine habit
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
	select {}
}
