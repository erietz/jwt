package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

func decode(s string) []byte {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return tokenBytes
}

func hash(header, payload, secret []byte, alg string) (string, error) {
	msg := fmt.Sprintf("%s.%s", header, payload)
	var signedMsg []byte

	switch alg {
	case "HS256":
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(msg))
		signedMsg = mac.Sum(nil)
	case "RS256":
		return "", errors.New("RS256 coming soon")
	default:
		return "", fmt.Errorf("Algorithms %s not implemented", alg)
	}

	return base64.RawURLEncoding.EncodeToString(signedMsg), nil
}
