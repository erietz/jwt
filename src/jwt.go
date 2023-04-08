package jwt

import (
	"encoding/json"
	"os"

	"github.com/hokaccha/go-prettyjson"
	"github.com/mattn/go-isatty"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type payload map[string]interface{}

type JWT struct {
	Header    header  `json:"header"`
	Payload   payload `json:"payload"`
	Signature string  `json:"signature"`
}

func (jwt JWT) String() string {
	var token []byte
	var err error

	if isatty.IsTerminal(os.Stdout.Fd()) {
		token, err = prettyjson.Marshal(jwt)
		if err != nil {
			panic(err)
		}
	} else {
		token, err = json.MarshalIndent(jwt, "", "    ")
		if err != nil {
			panic(err)
		}
	}

	return string(token)
}
