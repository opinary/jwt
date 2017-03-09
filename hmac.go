package jwt

import (
	"crypto"
	"crypto/hmac"
	"fmt"

	_ "crypto/sha256"
	_ "crypto/sha512"
)

type hmacSigner struct {
	alg   string
	keyID string
	key   []byte
	hash  crypto.Hash
}

var _ Signer = (*hmacSigner)(nil)
var _ Verifier = (*hmacSigner)(nil)

func (s *hmacSigner) Algorithm() string {
	return s.alg
}

func (s hmacSigner) KeyID() string {
	return s.keyID
}

func (s *hmacSigner) Sign(data []byte) ([]byte, error) {
	if !s.hash.Available() {
		return nil, ErrAlgorithmNotAvailable
	}

	hasher := hmac.New(s.hash.New, s.key)
	if _, err := hasher.Write(data); err != nil {
		return nil, fmt.Errorf("cannot encode data: %s", err)
	}
	return hasher.Sum(nil), nil
}

func (s *hmacSigner) Verify(signature, data []byte) error {
	if !s.hash.Available() {
		return ErrAlgorithmNotAvailable
	}

	hasher := hmac.New(s.hash.New, s.key)
	if _, err := hasher.Write(data); err != nil {
		return fmt.Errorf("cannot encode data: %s", err)
	}

	if !hmac.Equal(signature, hasher.Sum(nil)) {
		return ErrInvalidSignature
	}
	return nil
}

// HMAC256 returns signer using symetric key and SHA256 hashing function.
func HMAC256(key []byte, keyID string) Signer {
	return &hmacSigner{
		alg:   "HS256",
		keyID: keyID,
		key:   append([]byte{}, key...),
		hash:  crypto.SHA256,
	}
}

// HMAC384 returns signer using symetric key and SHA384 hashing function.
func HMAC384(key []byte, keyID string) Signer {
	return &hmacSigner{
		alg:   "HS384",
		keyID: keyID,
		key:   append([]byte{}, key...),
		hash:  crypto.SHA384,
	}
}

// HMAC512 returns signer using symetric key and SHA512 hashing function.
func HMAC512(key []byte, keyID string) Signer {
	return &hmacSigner{
		alg:   "HS512",
		keyID: keyID,
		key:   append([]byte{}, key...),
		hash:  crypto.SHA512,
	}
}
