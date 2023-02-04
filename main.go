package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

func decode(s string) []byte {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		color.HiRed(s)
		panic(err)
	}
	return tokenBytes
}

func indent(b []byte) string {
	s := &bytes.Buffer{}
	err := json.Indent(s, b, "", "    ")
	if err != nil {
		panic(err)
	}
	return s.String()
}

func hash(header, payload, secret []byte,) string {
	msg := fmt.Sprintf(
		"%s.%s",
		base64.RawURLEncoding.EncodeToString(header),
		base64.RawURLEncoding.EncodeToString(payload),
	)

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))

	sha := h.Sum(nil)
	return string(sha)
}

func main() {
	if len(os.Args) != 2 {
		color.HiRed("Usage: %s %s", os.Args[0], "jwt.string.here")
		os.Exit(1)
	}

	jwt := os.Args[1]

	parts := strings.Split(jwt, ".")

	if len(parts) != 3 {
		color.HiRed("Not a valid jwt")
		os.Exit(1)
	}

	header := decode(parts[0])
	payload := decode(parts[1])
	signature := parts[2]

	fmt.Printf(
		"%s.%s.%s\n",
		color.BlueString(parts[0]),
		color.MagentaString(parts[1]),
		color.CyanString(parts[2]),
	)

	headerJSON := indent(header)
	payloadJSON := indent(payload)

	fmt.Println()
	color.Blue(headerJSON)
	color.Magenta(payloadJSON)

	checksum := hash(header, payload, []byte("lkjsdlkfjsldkjf"))

	if checksum == string(decode(signature)) {
		color.Green("Token is valid")
	} else {
		color.HiRed("Token is invalid")
	}

	fmt.Println(checksum)
	fmt.Println(string(decode(signature)))
}
