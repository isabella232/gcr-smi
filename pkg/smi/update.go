package smi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Field struct {
	Agent      string
	Component  string
	Multiplier int
	SubService string
}

func Update(f Field, url, authkey string) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(f); err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-functions-key", authkey)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 201 {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("http error reply, status: %q, body: %q", res.Status, body)
	}
	return nil
}
