package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func handleFileSafe(w http.ResponseWriter, r *http.Request) {
	const baseDir = "/var/www/uploads"
	filename := r.URL.Query().Get("file")
	cleanPath := filepath.Clean(filepath.Join(baseDir, filename))
	if !strings.HasPrefix(cleanPath, baseDir+string(os.PathSeparator)) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	data, _ := os.ReadFile(cleanPath)
	w.Write(data)
}
