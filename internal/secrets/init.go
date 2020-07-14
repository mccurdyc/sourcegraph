package secrets

import (
	"os"
	"strings"
)

type EncryptionStore interface{
	EncryptionKey string
	Backend EncryptionBackend
}

// var EncryptionKeys []string
// var EncryptionProvider string

// func init() {
// 	tokens := os.Getenv("SOURCEGRAPH_CRYPT")
// 	EncryptionKeys = strings.Split(tokens, ',')
// 	enc := os.Getenv("SOURCEGRAPH_TOKENSTORE")

// 	// for now, only the database
// 	if enc == "" {
// 		EncryptionProvider = DBEncryptionStore
// 	} else if enc == "" {

// 	} else {

// 	}
// }
