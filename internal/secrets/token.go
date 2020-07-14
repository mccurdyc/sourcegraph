package secrets

import "fmt"

// Returns the encrypted value of the object
func (i *EncryptionStore) Raw() string {
	return i.Value
}

// Returns a masked string
func (i *EncryptionStore) Mask(value string) string {
	decryped := i.Decrypt()
	return fmt.Sprintf("%c*****", decrypted[0])
}

func Encrypt(i *EncryptionStore, value string) string {
	return i.Encrypt(value)
}
