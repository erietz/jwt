package jwt

import (
	"crypto"
	_ "crypto/sha256" // crypto.SHA256.New fails without this?
	_ "crypto/sha512" // crypto.SHA384.New and crypto.SHA512.New fails without this?
	"crypto/hmac"
	"encoding/base64"
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
		mac := hmac.New(crypto.SHA256.New, secret)
		mac.Write([]byte(msg))
		signedMsg = mac.Sum(nil)
	case "HS384":
		mac := hmac.New(crypto.SHA384.New, secret)
		mac.Write([]byte(msg))
		signedMsg = mac.Sum(nil)
	case "HS512":
		mac := hmac.New(crypto.SHA512.New, secret)
		mac.Write([]byte(msg))
		signedMsg = mac.Sum(nil)
	default:
		return "", fmt.Errorf("Algorithms %s not implemented", alg)
	}

	return base64.RawURLEncoding.EncodeToString(signedMsg), nil
}
