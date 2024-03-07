package commons

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// Dumper verbose logs
func Dumper(infos ...interface{}) {
	log.WithFields(log.Fields{
		"raw": infos,
	}).Info("dump")

}

// JSONify ...
func JSONify(infos ...interface{}) {
	j, _ := json.MarshalIndent(infos, "", "\t")
	fmt.Println(string(j))
}

// JSONString ...
func JSONString(info interface{}) string {
	j, _ := json.Marshal(info)
	return string(j)
}
