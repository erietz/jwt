package main

import (
	"flag"
	"io"
	"os"
	"strings"

	jwt "github.com/erietz/jwt/src"
	"github.com/fatih/color"
)


var secret string
var isSecretEncoded bool

func init() {
	const (
		secretDefault = ""
		secretUsage = "Secret used to encode the signature"
		isSecretEncodedDefault = false
		isSecretEncodedUsage = "If the secret itself is base64 encoded"
	)

	flag.StringVar(&secret, "s", secretDefault, secretUsage)
	flag.StringVar(&secret, "secret", secretDefault, secretUsage)

	flag.BoolVar(&isSecretEncoded, "e", isSecretEncodedDefault, isSecretEncodedUsage)
	flag.BoolVar(&isSecretEncoded, "isSecretEncoded", isSecretEncodedDefault, isSecretEncodedUsage)
}

func main() {
	flag.Parse()

	inputJWT := flag.Arg(0)
	if inputJWT == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}
		inputJWT = strings.TrimSuffix(string(data), "\n")
	}

	parts := strings.Split(inputJWT, ".")

	if len(parts) != 3 {
		color.HiRed("Not a valid jwt")
		os.Exit(1)
	}

	encodedToken := jwt.EncodedJWT{
		Header:          parts[0],
		Payload:         parts[1],
		Signature:       parts[2],
		Secret:          secret,
		IsSecretEncoded: isSecretEncoded,
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
