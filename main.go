package main

import (
	"crypto/des"
	"fmt"
)

func main() {
	key := []byte("bbbbbbbb")
	data := []byte("aaaaaaaa")

	cipher, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	out := make([]byte, 8)
	cipher.Encrypt(out, data)

	fmt.Printf("BYTES: %v\n", out)
}
