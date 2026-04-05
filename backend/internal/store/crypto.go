package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

const encryptedPasswordPrefix = "enc:v1:"

func EncryptPassword(plain string) ([]byte, error) {
	if plain == "" {
		return []byte(""), nil
	}

	key, hasKey := accountCryptoKey()
	if !hasKey {
		// Local/dev fallback to preserve startup if key is not configured.
		return []byte(plain), nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plain), nil)
	payload := append(nonce, ciphertext...)
	encoded := base64.StdEncoding.EncodeToString(payload)
	return []byte(encryptedPasswordPrefix + encoded), nil
}

func DecryptPassword(value []byte) (string, error) {
	raw := string(value)
	if raw == "" {
		return "", nil
	}
	if len(raw) < len(encryptedPasswordPrefix) || raw[:len(encryptedPasswordPrefix)] != encryptedPasswordPrefix {
		// Backward compatibility for old plaintext rows.
		return raw, nil
	}

	key, hasKey := accountCryptoKey()
	if !hasKey {
		return "", errors.New("ACCOUNT_CREDENTIALS_KEY is not configured")
	}

	encoded := raw[len(encryptedPasswordPrefix):]
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return "", errors.New("invalid encrypted payload")
	}

	nonce, ciphertext := payload[:nonceSize], payload[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}

func accountCryptoKey() ([]byte, bool) {
	raw := os.Getenv("ACCOUNT_CREDENTIALS_KEY")
	if raw == "" {
		return nil, false
	}

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err == nil && len(decoded) >= 32 {
		return decoded[:32], true
	}

	if len(raw) >= 32 {
		return []byte(raw[:32]), true
	}

	return nil, false
}
