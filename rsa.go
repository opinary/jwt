package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

type rsaSigner struct {
	alg   string
	keyID string
	key   *rsa.PrivateKey
	hash  crypto.Hash
}

var _ Signer = (*rsaSigner)(nil)

func (s *rsaSigner) Algorithm() string {
	return s.alg
}

func (s *rsaSigner) KeyID() string {
	return s.keyID
}

func (s *rsaSigner) Sign(data []byte) ([]byte, error) {
	if !s.hash.Available() {
		return nil, ErrAlgorithmNotAvailable
	}

	hasher := s.hash.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, fmt.Errorf("cannot hash: %s", err)
	}
	b := hasher.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, s.key, s.hash, b)
}

func (s *rsaSigner) Verify(signature, data []byte) error {
	if !s.hash.Available() {
		return ErrAlgorithmNotAvailable
	}

	hasher := s.hash.New()
	if _, err := hasher.Write(data); err != nil {
		return fmt.Errorf("cannot hash: %s", err)
	}
	b := hasher.Sum(nil)
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, s.hash, b, signature); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

type rsaVerifier struct {
	alg  string
	key  *rsa.PublicKey
	hash crypto.Hash
}

var _ Verifier = (*rsaVerifier)(nil)

func (v *rsaVerifier) Algorithm() string {
	return v.alg
}

func (v *rsaVerifier) Verify(signature, data []byte) error {
	if !v.hash.Available() {
		return ErrAlgorithmNotAvailable
	}

	hasher := v.hash.New()
	if _, err := hasher.Write(data); err != nil {
		return fmt.Errorf("cannot hash: %s", err)
	}
	b := hasher.Sum(nil)
	if err := rsa.VerifyPKCS1v15(v.key, v.hash, b, signature); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// RSA256Signer returns signer using asymmetric RSA algorithm to sign data.
//
// keyID is optional (can be empty) argument that is helpful when using several
// keys to sign data, to determine which key to use during verification.
func RSA256Signer(key *rsa.PrivateKey, keyID string) Signer {
	return &rsaSigner{
		alg:   "RS256",
		keyID: keyID,
		key:   key,
		hash:  crypto.SHA256,
	}
}

// RSA256Verifier returns verifier using asymmetric RSA algorithm to verify
// data signature.
func RSA256Verifier(key *rsa.PublicKey) Verifier {
	return &rsaVerifier{
		alg:  "RS256",
		key:  key,
		hash: crypto.SHA256,
	}
}

// RSA384Signer returns signer using asymmetric RSA algorithm to sign data.
//
// keyID is optional (can be empty) argument that is helpful when using several
// keys to sign data, to determine which key to use during verification.
func RSA384Signer(key *rsa.PrivateKey, keyID string) Signer {
	return &rsaSigner{
		alg:   "RS384",
		keyID: keyID,
		key:   key,
		hash:  crypto.SHA384,
	}
}

// RSA384Verifier returns verifier using asymmetric RSA algorithm to verify
// data signature.
func RSA384Verifier(key *rsa.PublicKey) Verifier {
	return &rsaVerifier{
		alg:  "RS384",
		key:  key,
		hash: crypto.SHA384,
	}
}

// RSA512Signer returns signer using asymmetric RSA algorithm to sign data.
//
// keyID is optional (can be empty) argument that is helpful when using several
// keys to sign data, to determine which key to use during verification.
func RSA512Signer(key *rsa.PrivateKey, keyID string) Signer {
	return &rsaSigner{
		alg:   "RS512",
		keyID: keyID,
		key:   key,
		hash:  crypto.SHA512,
	}
}

// RSA512Verifier returns verifier using asymmetric RSA algorithm to verify
// data signature.
func RSA512Verifier(key *rsa.PublicKey) Verifier {
	return &rsaVerifier{
		alg:  "RS512",
		key:  key,
		hash: crypto.SHA512,
	}
}
