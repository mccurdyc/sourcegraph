package secrets

import (
	"reflect"
	"testing"

	"github.com/sourcegraph/sourcegraph/internal/randstring"
)

// Test that encrypting and decryption the message yields the same value
func TestDBEncryptingAndDecrypting(t *testing.T) {
	// https://golang.org/pkg/crypto/aes/#NewCipher
	key := []byte(randstring.NewLen(32)) // AES-256
	db := DBEncryptionStore{EncryptionKey: key}
	toEncrypt := "i am the super secret string, shhhhh"

	encrypted, err := db.Encrypt(toEncrypt)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// better way to compare byte arrays
	if reflect.DeepEqual(encrypted, []byte(toEncrypt)) {
		t.Error("failed to encrypt")
		return
	}

	decrypted, err := db.Decrypt(encrypted)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if decrypted != toEncrypt {
		t.Errorf("failed to decrypt")
	}
}

// Test that different strings encrypt to different outputs
func TestDifferentOutputs(t *testing.T) {
	key := []byte(randstring.NewLen(32))
	db := DBEncryptionStore{EncryptionKey: key}
	messages := []string{
		"This may or may",
		"This is not the same as that",
		"The end of that",
		"Plants and animals",
		"Snow, igloos, sunshine, unicords",
	}

	var crypts []string
	for _, m := range messages {
		encrypted, _ := db.Encrypt(m)
		crypts = append(crypts, encrypted)
	}

	for _, c := range crypts {
		if isInSliceOnce(c, crypts) == false {
			t.Errorf("Duplicate encryption string: %v.", c)
			return
		}
	}
}

func isInSliceOnce(item string, slice []string) bool {
	found := 0
	for _, s := range slice {
		if item == s {
			found++
		}
	}

	return found == 1
}

func TestSampleNoRepeats(t *testing.T) {
	key := []byte(randstring.NewLen(32))
	toEncrypt := "All in, fall in, call in, wall in"
	db := DBEncryptionStore{EncryptionKey: key}

	var crypts []string
	for i := 0; i < 10000; i++ {
		encrypted, _ := db.Encrypt(toEncrypt)
		crypts = append(crypts, encrypted)
	}

	for _, item := range crypts {
		if isInSliceOnce(item, crypts) == false {
			t.Errorf("Duplicate encrypted string found.")
			return
		}
	}
}

// Test that rotating keys returns different encrypted strings
func TestDBKeyRotation(t *testing.T) {
	initialKey := []byte(randstring.NewLen(32))
	secondKey := []byte(randstring.NewLen(32))
	toEncrypt := "Chickens, pigs, giraffes, llammas, monkeys, birds, spiders"

	db := DBEncryptionStore{EncryptionKey: initialKey}
	encrypted, _ := db.Encrypt(toEncrypt) // another test validates

	reEncrypted, _ := db.RotateKey(secondKey, encrypted) // another test validates

	if reEncrypted == encrypted {
		t.Errorf("Failed to reencrypt the string.")
		return
	}

	// validate decrypting the message works with the new key
	anotherDB := DBEncryptionStore{EncryptionKey: secondKey}
	decrypted, err := anotherDB.Decrypt(reEncrypted)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if decrypted != toEncrypt {
		t.Errorf("failed to decrypt")
	}
}
