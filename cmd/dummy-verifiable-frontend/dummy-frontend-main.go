package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	var baseAPI string
	var baseDir string
	var port int

	flag.StringVar(&baseAPI, "api", "", "Base API URL for REST calls, e.g. https://server.example.com/dataset/foo")
	flag.StringVar(&baseDir, "dir", "assets/static", "Base DIR to serve JS and CSS and HTML from.")
	flag.IntVar(&port, "port", 8000, "PORT to listen on")
	flag.Parse()

	if baseAPI == "" {
		log.Fatal("must specify API base")
	}

	log.Printf("Serving... http://localhost:%d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.URL.String())
		// If no query, then we serve locally
		if r.URL.RawQuery == "" {
			rPath := path.Clean("/" + r.URL.Path)
			if rPath == "/" {
				rPath = "/index.html"
			}
			f, err := ioutil.ReadFile(filepath.Join(baseDir, filepath.FromSlash(rPath)))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ct := "application/binary"
			switch {
			case strings.HasSuffix(rPath, ".html"):
				ct = "text/html"
			case strings.HasSuffix(rPath, ".js"):
				ct = "application/javascript"
			case strings.HasSuffix(rPath, ".css"):
				ct = "text/css"
			}
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Content-Length", strconv.Itoa(len(f)))
			w.Write(f)
			return
		}

		// Try a GET against the server instead
		resp, err := http.Get(fmt.Sprintf("%s%s?%s", baseAPI, r.URL.Path, r.URL.RawQuery))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Write(b)
	})))
}
