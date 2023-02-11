package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

type Header struct {
	Alg string
	Typ string
}

type Payload map[string]interface{}

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

type JWT struct {
	Header    Header
	Payload   Payload
	Signature string
}

func (jwt EncodedJWT) Decode() JWT {
	var header Header
	err := json.Unmarshal(decode(jwt.Header), &header)
	if err != nil {
		panic(err)
	}

	var payload Payload
	err = json.Unmarshal(decode(jwt.Payload), &payload)
	if err != nil {
		panic(err)
	}

	return JWT{
		Header:    header,
		Payload:   payload,
		Signature: jwt.GenerateSignature(),
	}
}

// TODO: this method shouldn't go on the EncodedJWT since you need to know the
// algorithm to do the hash which comes from decoding the token...
func (jwt EncodedJWT) GenerateSignature() string {
	var secret []byte
	if jwt.IsSecretEncoded {
		secret = decode(jwt.Secret)
	} else {
		secret = []byte(jwt.Secret)
	}

	msg := fmt.Sprintf("%s.%s", jwt.Header, jwt.Payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	signedMsg := mac.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(signedMsg)
}

func (jwt JWT) PrettyPrint() {
	header, err := json.MarshalIndent(jwt.Header, "", "    ")
	if err != nil {
		panic(err)
	}
	payload, err := json.MarshalIndent(jwt.Payload, "", "    ")
	if err != nil {
		panic(err)
	}

	color.Blue(string(header))
	color.Magenta(string(payload))
}

func decode(s string) []byte {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		color.HiRed(s)
		panic(err)
	}
	return tokenBytes
}

func main() {
	if len(os.Args) != 2 {
		color.HiRed("Usage: %s %s", os.Args[0], "jwt.string.here")
		os.Exit(1)
	}

	parts := strings.Split(os.Args[1], ".")

	if len(parts) != 3 {
		color.HiRed("Not a valid jwt")
		os.Exit(1)
	}

	encodedJWT := EncodedJWT{
		Header:          parts[0],
		Payload:         parts[1],
		Signature:       parts[2],
		Secret:          "lkjsdlkfjsldkjf",
		IsSecretEncoded: false,
	}

	encodedJWT.PrettyPrint()
	jwt := encodedJWT.Decode()
	jwt.PrettyPrint()

	if jwt.Signature == encodedJWT.Signature {
		color.Green("Signature is verified")
	} else {
		color.HiRed("Invalid Signature")
	}

}
