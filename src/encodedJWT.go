package jwt

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

type EncodedJWT struct {
	Header          string
	Payload         string
	Signature       string
	Secret          string
	IsSecretEncoded bool
}

func (jwt EncodedJWT) String() string {
	var s string

	if isatty.IsTerminal(os.Stdout.Fd()) {
		fmt.Println("is a tty")
		s = fmt.Sprintf(
			"%s.%s.%s\n",
			color.BlueString(jwt.Header),
			color.MagentaString(jwt.Payload),
			color.CyanString(jwt.Signature),
		)
	} else {
		s = fmt.Sprintf("%s.%s.%s\n", jwt.Header, jwt.Payload, jwt.Signature)
	}

	return s
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
