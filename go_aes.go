package goaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func getCipherBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

func getGCM(block cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCM(block)
}

// Encrypt encrypts []byte data
func Encrypt(data []byte, key []byte) ([]byte, error) {
	var (
		block cipher.Block
		gcm   cipher.AEAD
		err   error
	)

	if block, err = getCipherBlock(key); err != nil {
		return nil, err
	}

	if gcm, err = getGCM(block); err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts []byte data
func Decrypt(data []byte, key []byte) ([]byte, error) {
	var (
		block cipher.Block
		gcm   cipher.AEAD
		err   error
	)

	if block, err = getCipherBlock(key); err != nil {
		return nil, err
	}

	if gcm, err = getGCM(block); err != nil {
		return nil, err
	}

	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}
