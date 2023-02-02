package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

func decode(s string) []byte {
	tokenBytes, err := base64.RawStdEncoding.DecodeString(s)
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
	signature := decode(parts[2])

	fmt.Printf(
		"%s.%s.%s\n",
		color.RedString(parts[0]),
		color.MagentaString(parts[1]),
		color.CyanString(parts[2]),
	)

	headerJSON := indent(header)
	payloadJSON := indent(payload)

	fmt.Println()
	color.Red(headerJSON)
	color.Magenta(payloadJSON)
	color.Cyan(string(signature))

}
