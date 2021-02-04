package cwebhook

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
)

const (
	HashAlgoSha1   = "sha1"
	HashAlgoSha256 = "sha256"
	HashAlgoSha512 = "sha512"

	Dot   = "."
	Equal = "="
)

func generateMAC(message, key []byte, hashFunc func() hash.Hash) []byte {
	mac := hmac.New(hashFunc, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func infoToMAC(timestamp, payload, secret []byte, hashFunc func() hash.Hash) []byte {
	message := make([]byte, 1, 1+len(timestamp)+len(payload))
	message = append(message, timestamp...)
	message = append(message, []byte(Dot)...)
	message = append(message, payload...)
	return generateMAC(message, secret, hashFunc)
}

func getHashFunc(hashAlgo string) (func() hash.Hash, error) {
	switch hashAlgo {
	case HashAlgoSha1:
		return sha1.New, nil
	case HashAlgoSha256:
		return sha256.New, nil
	case HashAlgoSha512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unknown hash algorithm: %v", hashAlgo)
	}
}

func CreateSignature(timestamp, payload, secret []byte, hashAlgo string) (string, error) {
	hashFunc, err := getHashFunc(hashAlgo)
	if err != nil {
		return "", err
	}

	mac := infoToMAC(timestamp, payload, secret, hashFunc)
	hexMAC := hex.EncodeToString(mac)
	signature := hashAlgo + Equal + hexMAC
	return signature, nil
}
