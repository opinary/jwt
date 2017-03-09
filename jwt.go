package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Verifier is the interface implemented by objects that can verify data
// signature.
// Verifier can only verify signature and cannot create one. This is because
// asymmetric algorithms use separate key for those processes.
type Verifier interface {
	// Algorithm returns JWS alg value as defined in RFC7518
	// https://tools.ietf.org/html/rfc7518#section-3.1
	Algorithm() string

	// Verify returns error if signature computed for given data is
	// different than expected values.
	Verify(signature, data []byte) error
}

// Signer is the interface implemented by objects that can compute data
// signature. In addition, every Signer is also Verifier.
type Signer interface {
	Verifier

	// Sign returns signature computed for given data.
	Sign(data []byte) ([]byte, error)
}

// Encode return claims serialized as signed JWT token. If Signer provides
// KeyID method, result is attached to header as signature key id ("kid").
func Encode(sig Signer, claims interface{}) ([]byte, error) {
	var keyID string
	if s, ok := sig.(namedKeyHolder); ok {
		keyID = s.KeyID()
	}

	header, err := encodeJSON(struct {
		Type      string `json:"typ"`
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid,omitempty"`
	}{
		Type:      "JWT",
		Algorithm: sig.Algorithm(),
		KeyID:     keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot encode header: %s", err)
	}

	content, err := encodeJSON(claims)
	if err != nil {
		return nil, fmt.Errorf("cannot encode claims: %s", err)
	}

	token := append(header, '.')
	token = append(token, content...)

	signature, err := sig.Sign(token)
	if err != nil {
		return nil, fmt.Errorf("cannot sign: %s", err)
	}
	signature, err = encode(signature)
	if err != nil {
		return nil, fmt.Errorf("cannot encode signature: %s", err)
	}

	token = append(token, '.')
	token = append(token, signature...)
	return token, nil
}

type namedKeyHolder interface {
	KeyID() string
}

// encodeJSON encode serialize given data into JSON and return it's base64
// representation with base64 padding removed.
func encodeJSON(jsonable interface{}) ([]byte, error) {
	b, err := json.Marshal(jsonable)
	if err != nil {
		return nil, err
	}
	return encode(b)
}

func encode(b []byte) ([]byte, error) {
	b64 := make([]byte, enc.EncodedLen(len(b)))
	enc.Encode(b64, b)
	b64 = bytes.TrimRight(b64, "=")
	return b64, nil
}

// DecodeClaims test JWT token signature and if valid, unpack claims to given
// structure.
//
// Validation is on purpose part of this function, so that it's not possible to
// extract claims from invalid tokens.
func DecodeClaims(token []byte, v Verifier, claims interface{}) error {
	chunks := bytes.Split(token, []byte("."))
	if len(chunks) != 3 {
		return ErrMalformedToken
	}

	// create big enough buffer
	buf := make([]byte, maxlen(chunks)+3)
	var b []byte

	// decode header
	if n, err := enc.Decode(buf, fixPadding(chunks[0])); err != nil {
		return fmt.Errorf("cannot base64 decode header: %s", err)
	} else {
		b = buf[:n]
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := json.Unmarshal(b, &header); err != nil {
		return fmt.Errorf("cannot JSON decode header: %s", err)
	}

	// decode claims
	if n, err := enc.Decode(buf, fixPadding(chunks[1])); err != nil {
		return fmt.Errorf("cannot base64 decode claims: %s", err)
	} else {
		b = buf[:n]
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return fmt.Errorf("cannot JSON decode claims: %s", err)
	}
	// decode extra claims that will be used later for the validation
	var lifetime struct {
		ExpirationTime int64 `json:"exp"`
		NotBefore      int64 `json:"nbf"`
	}
	if err := json.Unmarshal(b, &lifetime); err != nil {
		return fmt.Errorf("cannot JSON decode claims: %s", err)
	}

	if header.Algorithm != v.Algorithm() {
		return ErrInvalidSigner
	}
	// if header does contain key id and our validator does provide one as
	// well, match those two, because they must be the same
	if v, ok := v.(namedKeyHolder); ok && header.KeyID != "" {
		if v.KeyID() != header.KeyID {
			return ErrInvalidSigner
		}
	}

	// validate signature
	if n, err := enc.Decode(buf, fixPadding(chunks[2])); err != nil {
		return fmt.Errorf("cannot base64 decode signature: %s", err)
	} else {
		b = buf[:n]
	}
	beforeSign := token[:len(token)-len(chunks[2])-1]
	if err := v.Verify(b, beforeSign); err != nil {
		return err
	}

	// make sure token is still valid
	now := time.Now()
	if lifetime.ExpirationTime != 0 && lifetime.ExpirationTime < now.Unix() {
		return ErrExpired
	}
	if lifetime.NotBefore != 0 && lifetime.NotBefore > now.Unix() {
		return ErrNotReady
	}

	return nil
}

// DecodeHeader extract and decode header part of the JWT token into given
// header structure. Token is not validated, therefore sigature must be
// checked before extracted data can be trusted.
// Decoding header might be required before signature check, becase it may
// contain data relevant for signature computation like signing key id or used
// algorithm.
func DecodeHeader(token []byte, header interface{}) error {
	baseHeader := bytes.SplitN(token, []byte{'.'}, 2)[0]
	baseHeader = fixPadding(baseHeader)
	jsonHeader, err := enc.DecodeString(string(baseHeader))
	if err != nil {
		return fmt.Errorf("invalid base64 encoding: %s", err)
	}
	if err := json.Unmarshal([]byte(jsonHeader), &header); err != nil {
		return fmt.Errorf("invalid JSON: %s", err)
	}
	return nil
}

// maxlen returns length of the longest []byte element from given collection
func maxlen(a [][]byte) int {
	max := 0
	for _, b := range a {
		if l := len(b); l > max {
			max = l
		}
	}
	return max
}

// fixPadding return given base64 encoded string with padding characters added
// if necessary.
func fixPadding(b []byte) []byte {
	if n := len(b) % 4; n > 0 {
		res := make([]byte, len(b), len(b)+4)
		copy(res, b)
		return append(res, bytes.Repeat([]byte("="), 4-n)...)
	}
	return b
}

var (
	// ErrAlgorithmNotAvailable is returned when platform does not support
	// required cryptographic algorithm.
	ErrAlgorithmNotAvailable = errors.New("algorithm not available")

	// ErrInvalidSignature is returned when verification of data signature
	// fails, because to signature is incorrect.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrMalformedToken is returned when given token cannot be deserialized.
	ErrMalformedToken = errors.New("malformed token")

	// ErrInvalidSigner is returned when verifying data with verifier that
	// is using different algorithm than signer or used key ID is provided
	// within token and does not match one returned by verifier.
	ErrInvalidSigner = errors.New("invalid signer")

	// ErrExpired is returned when decoding token that expired.
	ErrExpired = errors.New("expired")

	// ErrNotReady is returned when decoding token that is defining not
	// before information and value is not yet expired.
	ErrNotReady = errors.New("token not yet active")
)

var enc = base64.URLEncoding
