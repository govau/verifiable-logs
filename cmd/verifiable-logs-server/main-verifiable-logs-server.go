package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/continusec/verifiabledatastructures/pb"

	"github.com/continusec/verifiabledatastructures/mutator/instant"
	"github.com/continusec/verifiabledatastructures/oracle/policy"
	"github.com/continusec/verifiabledatastructures/verifiable"
	"github.com/govau/cf-common/env"
	"github.com/govau/verifiable-logs/db"
	"github.com/govau/verifiable-logs/postgres"
)

func main() {
	app, err := cfenv.Current()
	if err != nil {
		log.Fatal(err)
	}
	envLookup := env.NewVarSet(
		env.WithOSLookup(), // Always look in the OS env first.
		env.WithUPSLookup(app, "verifiablelogs-ups"),
	)

	pgxPool, err := db.GetPGXPool(2)
	if err != nil {
		log.Fatal(err)
	}

	// Prepare a shutdown function
	shutdown := func() {
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

	db := &postgres.Storage{
		Pool: pgxPool,
	}

	service := &verifiable.Service{
		AccessPolicy: &policy.Static{
			Policy: []*pb.ResourceAccount{
				{
					Id: "data.gov.au",
					Policy: []*pb.AccessPolicy{
						{
							NameMatch: "*",
							Permissions: []pb.Permission{
								pb.Permission_PERM_LOG_PROVE_INCLUSION,
								pb.Permission_PERM_LOG_READ_ENTRY,
								pb.Permission_PERM_LOG_READ_HASH,
							},
							ApiKey:        "read",
							AllowedFields: []string{"*"},
						},
						{
							NameMatch: "*",
							Permissions: []pb.Permission{
								pb.Permission_PERM_LOG_RAW_ADD,
							},
							ApiKey:        "write",
							AllowedFields: []string{"*"},
						},
					},
				},
			},
		},
		Mutator: &instant.Mutator{
			Writer: db,
		},
		Reader: db,
	}

	server, err := service.Create()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Started up... waiting for ctrl-C.")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", envLookup.String("PORT", "8080")), (&generalisedtransparency.Server{
		Service: &verifiable.Client{
			Service: server,
		},
		Account:        "data.gov.au",
		ReadAPIKey:     "read",
		WriteAPIKey:    "write",
		Reader:         db,
		Writer:         db,
		ExternalAddKey: envLookup.MustString("VDB_SECRET"),
	}).CreateRESTHandler()))
}
