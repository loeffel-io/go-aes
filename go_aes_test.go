package goaes

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	tests := []struct {
		description          string
		key                  []byte
		data                 []byte
		expectedData         []byte
		expectedEncryptError error
		expectedDecryptError error
	}{
		{
			description:          "valid",
			key:                  []byte("{HtJt8;L2e7KVv6f3#TUyPJQ2p/cjw.="),
			data:                 []byte("my-password"),
			expectedData:         []byte("my-password"),
			expectedEncryptError: nil,
			expectedDecryptError: nil,
		},
		{
			description:          "invalid key size (48)",
			key:                  []byte("PpNYoA8@imQWWMvM=Zf;;72^DRYij2nU]dcV2fAoCav2uaUw"),
			data:                 []byte("my-password-2"),
			expectedData:         nil,
			expectedEncryptError: errors.New("crypto/aes: invalid key size 48"),
			expectedDecryptError: errors.New("crypto/aes: invalid key size 48"),
		},
	}

	for _, test := range tests {
		encrypted, err := Encrypt(test.data, test.key)

		if err != nil {
			assert.EqualError(t, err, test.expectedEncryptError.Error(), "Encrypt error should be equal")
		}

		decrypted, err := Decrypt(encrypted, test.key)

		if err != nil {
			assert.EqualError(t, err, test.expectedDecryptError.Error(), "Decrypt error should be equal")
		}

		assert.Equal(t, test.expectedData, decrypted)
	}
}
