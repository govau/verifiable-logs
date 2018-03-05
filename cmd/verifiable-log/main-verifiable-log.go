package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/continusec/verifiabledatastructures/assets"
	"github.com/continusec/verifiabledatastructures/pb"

	"github.com/continusec/verifiabledatastructures/mutator/instant"
	"github.com/continusec/verifiabledatastructures/oracle/policy"
	"github.com/continusec/verifiabledatastructures/server/httprest"
	"github.com/continusec/verifiabledatastructures/verifiable"
	"github.com/govau/cf-common/env"
	"github.com/govau/verifiable-log/db"
	"github.com/govau/verifiable-log/postgres"
)

func altHomePage(h http.Handler) http.Handler {
	css := append(assets.MustAsset("assets/static/main.css"), []byte(`
		#topheaderpart, #bottomfooterpart {
			display: none;
		}
	`)...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/main.css" {
			w.Header().Set("Content-Type", "text/css")
			w.Write(css)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func main() {
	app, err := cfenv.Current()
	if err != nil {
		log.Fatal(err)
	}
	envLookup := env.NewVarSet(
		env.WithOSLookup(), // Always look in the OS env first.
		env.WithUPSLookup(app, "govauverifiabledemo-ups"),
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
					Id: "1234",
					Policy: []*pb.AccessPolicy{
						{
							NameMatch:     "*",
							Permissions:   []pb.Permission{pb.Permission_PERM_ALL_PERMISSIONS},
							ApiKey:        envLookup.MustString("VDB_SECRET"),
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
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", envLookup.String("PORT", "8080")), altHomePage(httprest.CreateRESTHandler(server, nil, log.New(os.Stderr, "", log.LstdFlags)))))
}
