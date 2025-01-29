package aesutils

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func AESTest(t *testing.T, privateKey string, secretKey string) {
	hashedSecretKey, err := bcrypt.GenerateFromPassword([]byte(secretKey), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal("could not hash secret key, err", err)
	}

	key := string(hashedSecretKey[:32])

	encryptedPrivateKey, err := EncryptPrivateKey(privateKey, key)
	if err != nil {
		t.Fatal("failed to encrypt private key, err:", err)
	}
	decryptedPrivateKey, err := DecryptPrivateKey(encryptedPrivateKey, key)
	if err != nil {
		t.Fatal("failed to decrypt private key, err:", err)
	}
	if decryptedPrivateKey != privateKey {
		t.Fatal("mismatched decrypted private key")
	}
}

func TestAES(t *testing.T) {
	AESTest(t, "04b82f061b69471dc877ffc828687970da99fd2d65c6da7f08b9d9a793bf7262", "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47")
	AESTest(t, "randomstring", "abc123")
}
