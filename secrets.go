package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

var Manager *secret

// Secret empty struct
type secret struct {
	Password []byte
}

// NewSecret returns a Secret object implementation. I receives the encryption password as argument
func NewSecret(password string) *secret {
	return &secret{
		Password: []byte(password),
	}

}

// Encrypt string
func (s *secret) Encrypt(st string) (output string, err error) {

	plaintext := []byte(st)

	block, err := aes.NewCipher(s.Password)
	if err != nil {
		return "", err
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	output = base64.URLEncoding.EncodeToString(ciphertext)
	return output, nil
}

// Decrypt string
func (s *secret) Decrypt(st string) (output string, err error) {
	if st == "" {
		return st, fmt.Errorf("provided string cannot be empty")
	}

	ciphertext, _ := base64.URLEncoding.DecodeString(st)

	block, err := aes.NewCipher(s.Password)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	output = string(ciphertext)
	return output, nil
}

func Init(encryptionKey string) {
	Manager = NewSecret(encryptionKey)
}
