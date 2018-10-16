package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/continusec/verifiabledatastructures/mutator/instant"
	"github.com/continusec/verifiabledatastructures/oracle/policy"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/storage/memory"
	"github.com/continusec/verifiabledatastructures/storage/postgres"
	"github.com/continusec/verifiabledatastructures/verifiable"
	"github.com/govau/cf-common/env"
	"github.com/govau/cf-common/jobs"
	"github.com/govau/verifiable-logs/generalisedtransparency"
	"github.com/jackc/pgx"
)

func main() {
	envLookup := env.NewVarSet(
		env.WithOSLookup(), // Always look in the OS env first.
	)

	var db verifiable.StorageWriter
	if envLookup.String("NODB", "0") == "1" {
		db = &memory.TransientStorage{}
	} else {
		dbConnCount, err := strconv.Atoi(envLookup.String("DB_CONNECTIONS", "2"))
		if err != nil {
			log.Fatal(err)
		}

		pgxPool, err := pgx.NewConnPool(pgx.ConnPoolConfig{
			MaxConnections: dbConnCount,
			ConnConfig:     *jobs.MustPGXConfigFromCloudFoundry(),
		})
		if err != nil {
			log.Fatal(err)
		}
		db = &postgres.Storage{
			Pool: pgxPool,
		}
	}

	service := &verifiable.Service{
		AccessPolicy: &policy.Static{
			Policy: []*pb.ResourceAccount{
				{
					Id: "vin",
					Policy: []*pb.AccessPolicy{
						{
							NameMatch: "ownership",
							Permissions: []pb.Permission{
								pb.Permission_PERM_LOG_READ_ENTRY,
								pb.Permission_PERM_LOG_READ_HASH,
								pb.Permission_PERM_LOG_PROVE_INCLUSION,
							},
							ApiKey:        "read",
							AllowedFields: []string{"*"},
						},
						{
							NameMatch: "ownership",
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

	tnv, err := generalisedtransparency.NewWhitelistValidator([]string{"ownership"})
	if err != nil {
		log.Fatal(err)
	}

	inputValidator, err := generalisedtransparency.CreateTrustedCAValidator(envLookup.MustString("VINCA_PEM"), func(cert *x509.Certificate, data []byte) error {
		var rec struct {
			Timestamp    time.Time `json:"timestamp"`
			VIN          string    `json:"vin"`
			Jurisdiction string    `json:"jurisdiction"`
		}
		err = json.Unmarshal(data, &rec)
		if err != nil {
			return err
		}

		// Verify the date in the data can be signed by the cert
		if rec.Timestamp.Before(cert.NotBefore) || rec.Timestamp.After(cert.NotAfter) {
			return errors.New("data not signed during validity period")
		}

		// Verify the data is signed by the jurisdiction mentioned within
		if rec.Jurisdiction != cert.Subject.CommonName {
			return errors.New("data signed by the wrong jurisdiction")
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Started up... waiting for ctrl-C.")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", envLookup.String("PORT", "8080")), (&generalisedtransparency.Server{
		Service: &verifiable.Client{
			Service: server,
		},
		Account:            "vin",
		ReadAPIKey:         "read",
		WriteAPIKey:        "write",
		Reader:             db,
		Writer:             db,
		InputValidator:     inputValidator,
		TableNameValidator: tnv,
	}).CreateRESTHandler()))
}
