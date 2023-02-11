package main

import (
	"os"
	"strings"

	"github.com/erietz/jwt/src"
	"github.com/fatih/color"
)


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

	encodedToken := jwt.EncodedJWT{
		Header:          parts[0],
		Payload:         parts[1],
		Signature:       parts[2],
		Secret:          "lkjsdlkfjsldkjf",
		IsSecretEncoded: false,
	}

	token := encodedToken.Decode()

	encodedToken.PrettyPrint()
	token.PrettyPrint()

	if token.Signature == encodedToken.Signature {
		color.Green("Signature is verified")
	} else {
		color.HiRed("Invalid Signature")
	}

}
