package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/govau/verifiable-log/db"
)

func main() {
	/*app, err := cfenv.Current()
	if err != nil {
		log.Fatal(err)
	}*/
	/*envLookup := env.NewVarSet(
		env.WithOSLookup(), // Always look in the OS env first.
		env.WithUPSLookup(app, "certwatch-ups"),
	)*/

	pgxPool, err := db.GetPGXPool(10)
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

	log.Println("Started up... waiting for ctrl-C.")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Up and away.")
	})
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", os.Getenv("PORT")), nil))
}
