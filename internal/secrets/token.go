package secrets

import (
	"fmt"
)

func Mask(e *EncryptionStore, value string) (string, error) {
	str, err := e.Decrypt(value)
	if err != nil {
		return "", err
	}
	masked := fmt.Sprintf("%s*******", str[0])
	return masked, nil
}

func Raw(e *EncryptionStore, value string) (string, error) {
	return e.Decrypt(value)
}
