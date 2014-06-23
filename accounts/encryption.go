package accounts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	encryptionKey []byte
)

// Sets the encryption key to use. Must be a valid size AES encryption key (16, 24, or 32 bytes)
// Does not currently pad to accomadate
func SetEncryptionKey(key []byte) error {
	_, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	encryptionKey = key
	return nil
}

func SetEncryptionKeyString(key string) error {
	return SetEncryptionKey([]byte(key))
}

// encrypts data based on specified key
func encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if encryptionKey == nil || len(encryptionKey) == 0 {
		panic("Cannot store user information until encryption has been set")
	}

	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return
}

// descyrpts data based on specified key
func decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if encryptionKey == nil || len(encryptionKey) == 0 {
		panic("Cannot decrypt user information until encryption has been set")
	}

	block, err := aes.NewCipher(encryptionKey)

	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return
}
