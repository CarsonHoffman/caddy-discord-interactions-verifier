package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Verifier{})
	httpcaddyfile.RegisterHandlerDirective("discord", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var v Verifier
		err := v.UnmarshalCaddyfile(h.Dispenser)
		return v, err
	})
}

type Verifier struct {
	PublicKeyHex string `json:"public_key"`

	publicKey ed25519.PublicKey
	logger    *zap.Logger
}

func (Verifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.discord_interactions_verifier",
		New: func() caddy.Module { return new(Verifier) },
	}
}

func (v *Verifier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&v.PublicKeyHex) {
			return d.ArgErr()
		}
	}
	return nil
}

func (v *Verifier) Provision(ctx caddy.Context) error {
	if len(v.PublicKeyHex) != hex.EncodedLen(ed25519.PublicKeySize) {
		return fmt.Errorf("public key has invalid length of %d, needed %d",
			len(v.PublicKeyHex), hex.EncodedLen(ed25519.PublicKeySize))
	}

	p, err := hex.DecodeString(v.PublicKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	v.publicKey = p
	v.logger = ctx.Logger(v)

	return nil
}

func (v Verifier) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	timestamp := r.Header.Get("X-Signature-Timestamp")

	signatureHex := r.Header.Get("X-Signature-Ed25519")
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		v.logger.Warn("failed to decode X-Signature-Ed25519 header",
			zap.String("X-Signature-Ed25519", signatureHex),
			zap.Error(err),
		)
		w.WriteHeader(http.StatusUnauthorized)
		return err
	}

	b := bytes.NewBufferString(timestamp)
	_, err = io.Copy(b, r.Body)
	if err != nil {
		v.logger.Warn("failed to read from body",
			zap.Error(err),
		)
		w.WriteHeader(http.StatusUnauthorized)
		return err
	}

	verified := ed25519.Verify(v.publicKey, b.Bytes(), signature)
	if !verified {
		v.logger.Warn("signature verification failed",
			zap.String("public_key", v.PublicKeyHex),
			zap.String("signature", signatureHex),
			zap.String("verifying_message", b.String()),
		)
		w.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("signature verification failed")
	}

	v.logger.Info("signature verified")
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b.Bytes()[len(timestamp):]))
	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*Verifier)(nil)
	_ caddyhttp.MiddlewareHandler = (*Verifier)(nil)
	_ caddyfile.Unmarshaler       = (*Verifier)(nil)
)
