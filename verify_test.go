package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func TestVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	v := &Verifier{
		PublicKeyHex: hex.EncodeToString(pub),
		publicKey:    pub,
		logger:       zap.NewNop(),
	}

	for _, test := range []struct {
		name                 string
		body                 string
		modifySignature      bool
		nextShouldBeExecuted bool
		expectedStatus       int
	}{
		{
			name:                 "correct",
			body:                 `{"type":1}`,
			modifySignature:      false,
			nextShouldBeExecuted: true,
			expectedStatus:       http.StatusOK,
		},
		{
			name:                 "incorrect signature",
			body:                 `{"type":1}`,
			modifySignature:      true,
			nextShouldBeExecuted: false,
			expectedStatus:       http.StatusUnauthorized,
		},
		{
			name:                 "zero-length body",
			body:                 ``,
			modifySignature:      false,
			nextShouldBeExecuted: true,
			expectedStatus:       http.StatusOK,
		},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "http://no-op/", strings.NewReader(test.body))
		timestamp := fmt.Sprint(time.Now().Unix())
		r.Header.Set("X-Signature-Timestamp", timestamp)
		signature := ed25519.Sign(priv, []byte(timestamp+test.body))
		if test.modifySignature {
			// The choice of constants is completely arbitrary. Just flip one bit.
			signature[13] ^= 1
		}

		r.Header.Set("X-Signature-Ed25519", hex.EncodeToString(signature))

		nextExecuted := false
		next := func(w http.ResponseWriter, r *http.Request) error {
			nextExecuted = true
			b, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Errorf("got error reading body in next handler: %w", err)
			}

			if len(b) != len(test.body) {
				t.Errorf("body size incorrect in next handler: expected %d, got %d", len(test.body), len(b))
			}

			if string(b) != test.body {
				t.Errorf("body mismatch: expected %q, got %q", test.body, string(b))
			}

			return nil
		}

		v.ServeHTTP(w, r, caddyhttp.HandlerFunc(next))

		if w.Result().StatusCode != test.expectedStatus {
			t.Errorf("status code mismatch: expected %d, got %d", test.expectedStatus, w.Result().StatusCode)
		}

		if nextExecuted != test.nextShouldBeExecuted {
			t.Errorf("next handler execution state mismatch: expected %t, got %t", test.nextShouldBeExecuted, nextExecuted)
		}
	}
}
