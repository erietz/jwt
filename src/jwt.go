package jwt

import (
	"encoding/json"

	"github.com/fatih/color"
)

type header struct {
	Alg string
	Typ string
}

type payload map[string]interface{}

type JWT struct {
	Header    header
	Payload   payload
	Signature string
}

func (jwt JWT) PrettyPrint() {
	indent := "    "
	header, err := json.MarshalIndent(jwt.Header, "", indent)
	if err != nil {
		panic(err)
	}
	payload, err := json.MarshalIndent(jwt.Payload, "", indent)
	if err != nil {
		panic(err)
	}

	color.Blue(string(header))
	color.Magenta(string(payload))
}
