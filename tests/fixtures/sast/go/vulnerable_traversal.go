package main

import (
	"net/http"
	"os"
)

func handleFile(w http.ResponseWriter, r *http.Request) {
	// Vulnerable: raw parameter used directly in file opening
	filename := r.URL.Query().Get("file")
	data, _ := os.ReadFile("/var/www/uploads/" + filename)
	w.Write(data)
}
