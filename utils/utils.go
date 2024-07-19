package utils

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	attestationv1 "github.com/in-toto/attestation/go/v1"
	log "github.com/sirupsen/logrus"
)

func SaveAttestation(statements map[string]*attestationv1.Statement) error {
	dir := "attestations"
	log.Infof("Creating Directory %s...", dir)

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		reader := bufio.NewReader(os.Stdin)

		log.Printf("Directory %s already exists. Do you want to proceed? (y/n): ", dir)
		answer, _ := reader.ReadString('\n')

		answer = strings.TrimSpace(answer)
		answer = strings.ToLower(answer)

		if answer != "y" && answer != "yes" {
			log.Info("Operation aborted by the user.")
			return nil
		}
	} else {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return err
		}
	}

	for name, statement := range statements {
		fPath := filepath.Join(dir, name+".json")
		jsonData, err := json.Marshal(statement)
		if err != nil {
			return err
		}
		err = os.WriteFile(fPath, jsonData, os.ModePerm)
		if err != nil {
			return err
		}
		log.Infof("%s saved to %s\n", name, fPath)
	}

	return nil
}
