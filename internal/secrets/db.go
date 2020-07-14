package secrets

import (
	"github.com/sourcegraph/sourcegraph/internal/randstring"
	"crypto/aes"
	"crypto/cipher"

)

type DBEncryptionStore inteface {
	EncryptionKey string
}

// Returns an enrypted string
func (db *DBEncryptionStore) encrypt(key string, value string) (string, err) {


	// create a one time nonce of standard length
	nonce := randstring.NewLen(12)

	// initialize the cipher with our key
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	// create a tamper proof cipher with a specific mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// The nonce is now part of the encrypted string
	enc := gcm.Seal(nonce, nonce, []byte(value), nil)
	return enc, nil

}

// Encrypts the string, returning the encrypted value
func (db *DBEncryptionStore) Encrypt(value string) (string, err) {
	return db.encrypt(db.EncryptionKey, value)
}

// Decrypts the string, returning the decrypted value
func (db *DBEncryptionStore) Decrypt(encryptedValue string) (string, err) {
	block, err := aes.NewCipher(db.EncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// get back the nonce and the encrypted string
	nonce, crypt := encryptedValue[:gcm.NonceSize()], encryptedValue[:gcp.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, crypt, nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// This function rotates the encryption used on an item by decryping and then recencrypting
func (db *DBEncryptionStore) Rotate(newKey string, encryptedValue string) (string, err) {
	decrypted, err := db.Decrypt(encryptedValue)
	if err != nil {
		return nil, err
	}

	return db.encrypt(newKey, decrypted)
}
