package jwt

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
)

type EncodedJWT struct {
	Header          string
	Payload         string
	Signature       string
	Secret          string
	IsSecretEncoded bool
}

func (jwt EncodedJWT) PrettyPrint() {
	fmt.Printf(
		"%s.%s.%s\n",
		color.BlueString(jwt.Header),
		color.MagentaString(jwt.Payload),
		color.CyanString(jwt.Signature),
	)
}

func (jwt EncodedJWT) Decode() JWT {
	var header header
	err := json.Unmarshal(decode(jwt.Header), &header)
	if err != nil {
		panic(err)
	}

	var payload payload
	err = json.Unmarshal(decode(jwt.Payload), &payload)
	if err != nil {
		panic(err)
	}

	var secret []byte
	if jwt.IsSecretEncoded {
		secret = decode(jwt.Secret)
	} else {
		secret = []byte(jwt.Secret)
	}

	signature, err := hash([]byte(jwt.Header), []byte(jwt.Payload), secret, header.Alg)
	if err != nil {
		panic(err)
	}

	return JWT{
		Header:    header,
		Payload:   payload,
		Signature: signature,
	}
}
