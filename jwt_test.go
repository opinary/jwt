package jwt

import (
	"fmt"
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {
	cases := map[string]struct {
		signer    Signer
		claims    interface{}
		wantToken string
		wantErr   error
	}{
		"ok-none-signer": {
			signer:    noneSigner{},
			claims:    map[string]string{"foo": "bar"},
			wantToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.",
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

func TestDecodeHeader(t *testing.T) {
	const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Inh5ei1rZXkifQ.eyJjb2xvciI6InJlZCIsInNjb3JlIjo0fQ.bCkZqyQ5YewRrEujnM0If48PDqiiNzm02FAYpBvjtbu_qs3AC7573piNib7uZ6yeIKTk6lY9P-vyaGynVdAJtnUF2boAzP4vDWix3lSxWSDNXQePpuPTP6M7IWgzIYTBPRVXUqQrfvNFW7VZl33mJ5sGIkIG2WfTc6-Wn4K6niA"
	var header struct {
		Type      string `json:"typ"`
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := DecodeHeader([]byte(token), &header); err != nil {
		t.Fatalf("cannot decode header: %s", err)
	}

	if header.Type != "JWT" {
		t.Fatalf("want type JWT, got %+v", header)
	}
	if header.Algorithm != "RS256" {
		t.Fatalf("want algorithm RS256, got %+v", header)
	}
	if header.KeyID != "xyz-key" {
		t.Fatalf("want key id xyz-key, got %+v", header)
	}
}

func TestDecodeClaim(t *testing.T) {
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

type noneSigner struct{}

func (noneSigner) Algorithm() string {
	return "none"
}

func (noneSigner) Verify(signature, data []byte) error {
	return nil
}

func (noneSigner) Sign(data []byte) ([]byte, error) {
	return []byte{}, nil
}

func ExampleEncode() {
	// define payload that will be used as JWT claims
	type Payload struct {
		Email string `json:"email"`
		Admin bool   `json:"admin"`

		// JWT specific claims as defined in
		// https://tools.ietf.org/html/rfc7519#section-4.1
		ExpirationTime int64 `json:"exp"`
	}

	var signer Signer = HMAC256([]byte(`asdosiahodihqw8qwhqpwfjpfoafphpfwhpqf`), "")

	// create JWT token using given signer
	token, err := Encode(signer, &Payload{
		Email:          "john.smith@example.com",
		Admin:          true,
		ExpirationTime: 2889062211,
	})
	if err != nil {
		fmt.Println("cannot create token:", err)
	} else {
		fmt.Println("token:", string(token))
	}
}

func ExampleDecodeClaims() {
	token := []byte(`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImpvaG4uc21pdGhAZXhhbXBsZS5jb20iLCJhZG1pbiI6dHJ1ZSwiZXhwIjoyODg5MDYyMjExfQ.JS9RziTEy6dcA9DC6z6aYoiG8RnpfmPY4eoY_6_uc1U`)

	// define payload that will be used as JWT claims
	type Payload struct {
		Email string `json:"email"`
		Admin bool   `json:"admin"`

		// JWT specific claims as defined in
		// https://tools.ietf.org/html/rfc7519#section-4.1
		ExpirationTime int64 `json:"exp"`
	}

	var verifier Verifier = HMAC256([]byte(`asdosiahodihqw8qwhqpwfjpfoafphpfwhpqf`), "")

	var payload Payload
	switch err := DecodeClaims(token, verifier, &payload); err {
	case nil:
		fmt.Printf("payload: %v\n", payload)
	case ErrExpired:
		fmt.Println("please refresh your tokne")
	default:
		fmt.Println("invalid token:", err)
	}
	// Output: payload: {john.smith@example.com true 2889062211}
}
