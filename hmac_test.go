package jwt

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestSigners(t *testing.T) {
	signers := []Signer{
		HMAC256([]byte("top secret 3215125"), "keyid-hr21o"),
		HMAC384([]byte("top secret 8199421"), "keyid-901u4"),
		HMAC512([]byte("top secret 0024142"), "keyid-8r109"),
	}
	data := []byte(time.Now().String())

	for _, sig := range signers {
		got, err := sig.Sign(data)
		if err != nil {
			t.Errorf("%s: cannot sign: %s", sig.Algorithm(), err)
			continue
		}
		if err := sig.Verify(got, data); err != nil {
			t.Errorf("%s: cannot verify signature: %s", sig.Algorithm(), err)
			continue
		}
	}
}

func TestDecodeClaimHMAC(t *testing.T) {
	secret := []byte(`secret used to sign data`)

	type claim struct {
		Color string `json:"color"`
		Score int    `json:"score"`
	}

	cases := map[string]struct {
		token        string
		verifier     Verifier
		wantClaim    claim
		wantErr      bool
		wantExactErr error
	}{
		"ok-hmac-256": {
			token:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjEyMyJ9.eyJjb2xvciI6ImJsdWUiLCJzY29yZSI6Nn0.d2zOhna6IjzgEGkRjz6yhI-sTj-yvzDT3C2u_AZimTE",
			verifier: HMAC256(secret, "123"),
			wantErr:  false,
			wantClaim: claim{
				Color: "blue",
				Score: 6,
			},
		},
		"ok-hmac-384": {
			token:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCIsImtpZCI6IjEyMyJ9.eyJjb2xvciI6ImJsdWUiLCJzY29yZSI6Nn0.HRBJPgqBAymueZEstqYF1n9pfrwf_t4Rmh61fLoysmuMvYYVHpXmkxsbzGzcCt2v",
			verifier: HMAC384(secret, "123"),
			wantErr:  false,
			wantClaim: claim{
				Color: "blue",
				Score: 6,
			},
		},
		"ok-hmac-512": {
			token:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6IjEyMyJ9.eyJjb2xvciI6ImJsdWUiLCJzY29yZSI6Nn0.PVK7xlv1oBHbYJv8iAtDHNJ5eLhxcxODDncja8HzDVm823xORN_p9sNLpgc4JabzVPxLaxWCRkqeceZf-I35xw",
			verifier: HMAC512(secret, "123"),
			wantErr:  false,
			wantClaim: claim{
				Color: "blue",
				Score: 6,
			},
		},
	}

	for tname, tc := range cases {
		var c claim
		err := DecodeClaims([]byte(tc.token), tc.verifier, &c)
		if (err == nil) == tc.wantErr {
			t.Errorf("%s: want error %v, got %q", tname, tc.wantErr, err)
			continue
		}
		if tc.wantExactErr != nil && err != tc.wantExactErr {
			t.Errorf("%s: want error %q, got %q", tname, tc.wantExactErr, err)
			continue
		}
		if err == nil && !reflect.DeepEqual(c, tc.wantClaim) {
			t.Errorf("%s: want claim %+v, got %+v", tname, tc.wantClaim, c)
			continue
		}
	}
}

func ExampleHMAC256() {
	secret := []byte(`9u109qfiophfqwihyqwofihiugblwaigfaui`)
	signer := HMAC256(secret, "")

	// define payload that will be used as JWT claims
	type Payload struct {
		UserEmail   string `json:"email"`
		UserIsAdmin bool   `json:"admin"`

		// JWT specific claims as defined in
		// https://tools.ietf.org/html/rfc7519#section-4.1
		ExpirationTime int64 `json:"exp"`
	}

	// create JWT token using given HMAC algorithm as signer
	token, err := Encode(signer, &Payload{
		UserEmail:      "john.smith@example.com",
		UserIsAdmin:    true,
		ExpirationTime: time.Now().Add(3 * time.Hour).Unix(),
	})
	if err != nil {
		panic(err)
	}

	// decode token, but extract only user email - we can safely ignore any
	// fields that we are not interested in
	var claims struct {
		UserEmail string `json:"email"`
	}
	switch err := DecodeClaims(token, signer, &claims); err {
	case nil:
		// token is valid and claims structure was successfuly filled
		// with payload data
		fmt.Println("user email:", claims.UserEmail)
	case ErrExpired:
		// although we did not extract ExpirationTime from the payload,
		// token is still validated and if expired, error is returned
		fmt.Println("please review your token")
	default:
		fmt.Println("invalid token:", err)
	}
}
