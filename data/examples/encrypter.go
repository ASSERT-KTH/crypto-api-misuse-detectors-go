package main

import (
	"crypto/rand"
	"crypto/rsa"
)

type Encrypter struct {
	KeyLength int
}

var BasicLength = 1024

func GenKey(e *Encrypter) *rsa.PrivateKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, e.KeyLength+BasicLength) // Taint sink (param 2??)
	return privateKey
}

func main() {
	encrypter := Encrypter{KeyLength: 128} // Taint source
	GenKey(&encrypter)
}
