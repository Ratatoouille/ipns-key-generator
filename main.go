package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/libp2p/go-libp2p-core/crypto"
)

const keyFilenamePrefix = "key_"

var codec = base32.StdEncoding.WithPadding(base32.NoPadding)

func encode(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("key name must be at least one character")
	}

	encodedName := codec.EncodeToString([]byte(name))
	log.Printf("Encoded key name: %s to: %s", name, encodedName)

	return keyFilenamePrefix + strings.ToLower(encodedName), nil
}

func Put(name string, k crypto.PrivKey) error {
	name, err := encode(name)
	if err != nil {
		return err
	}

	b, err := crypto.MarshalPrivateKey(k)
	if err != nil {
		return err
	}

	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	kp := filepath.Join(dirname, name)

	fi, err := os.OpenFile(kp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	defer fi.Close()

	_, err = fi.Write(b)

	return err
}

func main() {
	var sk crypto.PrivKey

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		log.Println(err)
	}

	sk = priv

	err = Put(os.Args[1], sk)
	if err != nil {
		log.Println(err)
	}
}
