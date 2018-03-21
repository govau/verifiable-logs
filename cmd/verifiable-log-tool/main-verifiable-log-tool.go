package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"

	"github.com/govau/verifiable-logs/generalisedtransparency"
)

func main() {
	var url string
	var addAPIKey string
	var action string
	var treeSize int

	flag.StringVar(&url, "url", "", "base URL for log")
	flag.StringVar(&action, "action", "", "base URL for log")
	flag.StringVar(&addAPIKey, "key", "", "API key for adding (optional)")
	flag.IntVar(&treeSize, "size", 0, "tree size (optional)")
	flag.Parse()

	if url == "" {
		log.Println("url must be specified")
		os.Exit(1)
	}

	vlog := &generalisedtransparency.LogClient{
		URL:       url,
		AddAPIKey: addAPIKey,
	}

	switch action {
	case "":
		log.Println("action must be specified")
		os.Exit(1)

	case "entries":
		reader, err := vlog.GetReadClient()
		if err != nil {
			log.Fatal(err)
		}

		sth, err := reader.GetSTH(context.Background())
		if err != nil {
			log.Fatal(err)
		}

		entries, err := reader.GetEntries(context.Background(), 0, int64(sth.TreeSize)-1)
		if err != nil {
			log.Fatal(err)
		}

		// Verify STH using https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-28#section-2.1.2
		var stack [][sha256.Size]byte
		for idx, entry := range entries {
			leafData, err := tls.Marshal(entry.Leaf)
			if err != nil {
				log.Fatal(err)
			}

			stack = append(stack, sha256.Sum256(append([]byte{0}, leafData...)))
			for i := idx; (i % 2) == 1; i >>= 1 {
				stack = append(stack[:len(stack)-2], sha256.Sum256(append(append([]byte{1}, stack[len(stack)-2][:]...), stack[len(stack)-1][:]...)))
			}

			// Verify the object hash
			if entry.Leaf.TimestampedEntry.EntryType != ct.XObjectHashLogEntryType {
				log.Fatal("log entry not of type object hash")
			}
			//log.Println("verified object hash for entry matches that in leaf")

			expectedObjectHash, err := objecthash.ObjectHash(entry.ObjectData)
			if err != nil {
				log.Fatal(err)
			}

			if expectedObjectHash != entry.ObjectHash {
				log.Fatal("wrong object hash for data")
			}

			dataAsText, err := json.Marshal(entry.ObjectData)
			if err != nil {
				log.Fatal(err)
			}

			log.Printf("#%d: %s\n", idx, dataAsText)
		}

		for len(stack) != 1 {
			stack = append(stack[:len(stack)-2], sha256.Sum256(append(append([]byte{1}, stack[len(stack)-2][:]...), stack[len(stack)-1][:]...)))
		}

		if sth.SHA256RootHash != stack[0] {
			log.Fatalf("received root hash: %s, calculated root hash: %s\n", sth.SHA256RootHash.Base64String(), ct.SHA256Hash(stack[0]).Base64String())
		}

		//log.Println("verified root hash in sth matches that calculated by get-entries")

	default:
		log.Println("unrecognized action")
		os.Exit(1)
	}
}
