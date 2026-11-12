// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedJwtVerifiesWithTheKeyInItsHeader(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwt, err := sign(key, "dpop+jwt", map[string]any{"htm": "POST"})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}
	var header struct {
		Typ string            `json:"typ"`
		Alg string            `json:"alg"`
		Jwk map[string]string `json:"jwk"`
	}
	decode(t, parts[0], &header)
	if header.Typ != "dpop+jwt" || header.Alg != "ES256" {
		t.Errorf("header = %+v, want typ dpop+jwt and alg ES256", header)
	}
	pub := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(unb64(t, header.Jwk["x"])),
		Y:     new(big.Int).SetBytes(unb64(t, header.Jwk["y"])),
	}
	sig := unb64(t, parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&pub, digest[:],
		new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("signature does not verify with the header jwk")
	}
}

func TestThumbprintMatchesTheServer(t *testing.T) {
	// The P-256 generator point as a public key; the expected value is computed by Nimbus.
	p256 := elliptic.P256().Params()
	key := ecdsa.PublicKey{Curve: elliptic.P256(), X: p256.Gx, Y: p256.Gy}

	got, err := thumbprint(&key)
	if err != nil {
		t.Fatal(err)
	}

	if want := "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"; got != want {
		t.Errorf("thumbprint = %s, want %s", got, want)
	}
}

func TestTheDeviceKeyIsReusedOnceCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-key.pem")

	created, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}

	if !created.Equal(loaded) {
		t.Error("the loaded key differs from the created one")
	}
}

func decode(t *testing.T, part string, v any) {
	t.Helper()
	if err := json.Unmarshal(unb64(t, part), v); err != nil {
		t.Fatal(err)
	}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
