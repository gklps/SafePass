package aesutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Encrypt the private key using AES-GCM
func EncryptPrivateKey(privateKey, secretKey string) (string, error) {
	// Create an AES cipher
	block, err := aes.NewCipher([]byte(secretKey)[:32])
	if err != nil {
		fmt.Println("failed to create an aes cipher")
		return "", err
	}

	// Use AES-GCM for encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("failed to create aes gcm")
		return "", err
	}

	// Generate a random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		fmt.Println("failed to create a random nonce")
		return "", err
	}

	// Encrypt the private key
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(privateKey), nil)

	// Return encrypted data as base64
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt the private key
func DecryptPrivateKey(encryptedKey, secretKey string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedKey)
	if err != nil {
		return "", nil
	}

	// Create an AES cipher
	block, err := aes.NewCipher([]byte(secretKey)[:32])
	if err != nil {
		return "", err
	}

	// Use AES-GCM for decryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the private key
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
