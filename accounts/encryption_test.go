package accounts

import (
	"crypto/aes"
	. "gopkg.in/check.v1"
)

func (s *MySuite) TestEncryption(c *C) {
	key := []byte("my test key 1234")
	plaintext := []byte("my secret message")
	SetEncryptionKey(key)
	ciphertext, err := encrypt(plaintext)
	c.Assert(err, IsNil)
	// make sure it's the correct format
	c.Assert(ciphertext, HasLen, len(plaintext)+aes.BlockSize)
	// assert it returned correctly
	plaintext2, err := decrypt(ciphertext)
	c.Assert(err, IsNil)
	// Have to use deep equals because of byte types
	c.Assert(plaintext, DeepEquals, plaintext2)
}
