package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"
)

func init() {
	// use external service to verify tokens, for example:
	//
	// 	https://jwt.io
	//
	block, _ := pem.Decode([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----
	`))
	/*
	   -----BEGIN PUBLIC KEY-----
	   MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
	   6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
	   Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
	   oYi+1hqp1fIekaxsyQIDAQAB
	   -----END PUBLIC KEY-----
	*/
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	privRSA = key
}

var privRSA *rsa.PrivateKey

func TestEncodeRSA(t *testing.T) {
	cases := map[string]struct {
		signer    Signer
		claims    interface{}
		wantToken string
		wantErr   error
	}{
		"ok-rsa256-signer": {
			signer: RSA256Signer(privRSA, "xyz-key"),
			claims: map[string]interface{}{
				"color": "red",
				"score": 4,
			},
			wantToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Inh5ei1rZXkifQ.eyJjb2xvciI6InJlZCIsInNjb3JlIjo0fQ.bCkZqyQ5YewRrEujnM0If48PDqiiNzm02FAYpBvjtbu_qs3AC7573piNib7uZ6yeIKTk6lY9P-vyaGynVdAJtnUF2boAzP4vDWix3lSxWSDNXQePpuPTP6M7IWgzIYTBPRVXUqQrfvNFW7VZl33mJ5sGIkIG2WfTc6-Wn4K6niA",
		},
	}

	for tname, tc := range cases {
		token, err := Encode(tc.signer, tc.claims)
		if token := string(token); tc.wantToken != token {
			t.Errorf("%s: want %q token, got %q", tname, tc.wantToken, token)
			continue
		}
		if err != tc.wantErr {
			t.Errorf("%s: want %q error, got %q", tname, tc.wantErr, err)
			continue
		}
	}
}

func TestDecodeClaimRSA(t *testing.T) {
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
		"ok-rsa-256": {
			token:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Inh5ei1rZXkifQ.eyJjb2xvciI6InJlZCIsInNjb3JlIjo0fQ.bCkZqyQ5YewRrEujnM0If48PDqiiNzm02FAYpBvjtbu_qs3AC7573piNib7uZ6yeIKTk6lY9P-vyaGynVdAJtnUF2boAzP4vDWix3lSxWSDNXQePpuPTP6M7IWgzIYTBPRVXUqQrfvNFW7VZl33mJ5sGIkIG2WfTc6-Wn4K6niA",
			verifier: RSA256Verifier(&privRSA.PublicKey),
			wantErr:  false,
			wantClaim: claim{
				Color: "red",
				Score: 4,
			},
		},
		"ok-rsa-256-2": {
			token:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNlY3JldCJ9.eyJjb2xvciI6ImJsdWUiLCJzY29yZSI6Nn0.DpvdCvH5gF0_WcSDFWk4iUb8w2k5dMIeyraatl03Foqf8LDRH4PUvMKQtcE0P_1llZqw9GsIbQb8OtjgC5a32rEvoU_hm5gkUhLX87l8RjqS2CbDEA4dKNuyyT-BUx5KBsd9p0GkS8kZCPDfcUTDRNxqflfGtzj9p_V0VXG7wTg",
			verifier: RSA256Verifier(&privRSA.PublicKey),
			wantErr:  false,
			wantClaim: claim{
				Color: "blue",
				Score: 6,
			},
		},
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
		"malformed-token": {
			token:        "this-does-not-even-have-dots",
			verifier:     RSA256Verifier(&privRSA.PublicKey),
			wantErr:      true,
			wantExactErr: ErrMalformedToken,
		},
		"malformed-json": {
			token:    "Zm9vCg.Zm9vCg.Zm9vCg",
			verifier: RSA256Verifier(&privRSA.PublicKey),
			wantErr:  true,
		},
		"invalid-signature": {
			token:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNlY3JldCJ9.eyJjb2xvciI6ImJsdWUiLCJzY29yZSI6Nn0.xxxxxxxxxxxxxxxxxx",
			verifier: RSA256Verifier(&privRSA.PublicKey),
			wantErr:  true,
		},
		"expired": {
			token:        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNlY3JldCJ9.eyJleHAiOjEyMzR9.BcqP4E1KoT4XOH7Xh0d19PYjTMHVnr1wRYH0OhMv1V8Tqm8X2AijKlncHIGJrmssWaCA5RYsSf6x1fPWCDZez9fh-P1QpaZ-X0NXyrvgPmzREgPYqRJ6kfpRfw4J9UaM-LV0b-RWqlzczmh8-F1qmCTME7pGM0rp21uI5RyYquU",
			verifier:     RSA256Verifier(&privRSA.PublicKey),
			wantErr:      true,
			wantExactErr: ErrExpired,
		},
		"not-yet-ready": {
			token:        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNlY3JldCJ9.eyJuYmYiOjY0Nzg3OTMxMTV9.tXDV1FMPnG3oKFn3wnheI7kzPvTeIY52GuOcY7iqBf9gR-QQcYqpJmAdiUZnRg6xI8UhUvpK6Rbrbnfr7TqXvJ7gMyCmdJxYJKTCiRaDQ0dH0OVltgQRexFSXbTZG66KGkn6R1_QnUp4FgUhuyDTM1RAxxYZd-5O5p37p4BSnl8",
			verifier:     RSA256Verifier(&privRSA.PublicKey),
			wantErr:      true,
			wantExactErr: ErrNotReady,
		},
		"invalid-signer": {
			token:        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNlY3JldCJ9.eyJuYmYiOjY0Nzg3OTMxMTV9.tXDV1FMPnG3oKFn3wnheI7kzPvTeIY52GuOcY7iqBf9gR-QQcYqpJmAdiUZnRg6xI8UhUvpK6Rbrbnfr7TqXvJ7gMyCmdJxYJKTCiRaDQ0dH0OVltgQRexFSXbTZG66KGkn6R1_QnUp4FgUhuyDTM1RAxxYZd-5O5p37p4BSnl8",
			verifier:     noneSigner{},
			wantErr:      true,
			wantExactErr: ErrInvalidSigner,
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
