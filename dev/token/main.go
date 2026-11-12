// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

// Command token signs in to a local authorization server with a device key, the way the wallet
// app does: a jwt-bearer assertion plus a DPoP proof, both signed by the device key when the
// request is sent. It prints the response and the decoded access token.
//
// The device key is kept in a local file and created on first use, so the server can register
// it in the dev profile. -thumbprint prints the key's RFC 7638 thumbprint and exits.
//
// Usage: go run . [-key file] [-thumbprint] [issuer]   (default http://localhost:9000)
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const clientID = "wallet-app"

func main() {
	keyFile := flag.String("key", "device-key.pem", "device key file, created if missing")
	printThumbprint := flag.Bool("thumbprint", false, "print the device key thumbprint and exit")
	flag.Parse()
	issuer := "http://localhost:9000"
	if flag.NArg() > 0 {
		issuer = strings.TrimSuffix(flag.Arg(0), "/")
	}
	tokenURL := issuer + "/oauth2/token"

	key, err := loadOrCreateKey(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	jkt, err := thumbprint(&key.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	if *printThumbprint {
		fmt.Println(jkt)
		return
	}
	now := time.Now().Unix()
	assertion, err := sign(key, "JWT", map[string]any{
		"iss": clientID, "sub": clientID, "aud": issuer,
		"iat": now, "exp": now + 60, "jti": newID(),
	})
	if err != nil {
		log.Fatal(err)
	}
	dpop, err := sign(key, "dpop+jwt", map[string]any{
		"htm": http.MethodPost, "htu": tokenURL, "iat": now, "jti": newID(),
	})
	if err != nil {
		log.Fatal(err)
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
		"client_id":  {clientID},
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpop)

	fmt.Printf("POST %s\nDevice key %s\n\n", tokenURL, jkt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("HTTP %s\n%s\n", resp.Status, pretty(body))
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &token) == nil && token.AccessToken != "" {
		parts := strings.Split(token.AccessToken, ".")
		for i, name := range []string{"header", "payload"} {
			raw, _ := base64.RawURLEncoding.DecodeString(parts[i])
			fmt.Printf("\nAccess token %s:\n%s\n", name, pretty(raw))
		}
	}
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}

// loadOrCreateKey reads a PKCS #8 PEM P-256 key from path, or creates and saves a new one.
func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return createKey(path)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: not a P-256 key", path)
	}
	return key, nil
}

func createKey(path string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// publicJWK returns the public key as a JWK with only the members RFC 7638 requires.
func publicJWK(key *ecdsa.PublicKey) (map[string]string, error) {
	pub, err := key.ECDH()
	if err != nil {
		return nil, err
	}
	point := pub.Bytes() // 0x04 || X || Y
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64(point[1:33]),
		"y":   b64(point[33:65]),
	}, nil
}

// thumbprint returns the RFC 7638 thumbprint of the key, the value the server puts in cnf.jkt.
func thumbprint(key *ecdsa.PublicKey) (string, error) {
	jwk, err := publicJWK(key)
	if err != nil {
		return "", err
	}
	// encoding/json sorts map keys, which gives the member order RFC 7638 requires.
	canonical, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return b64(digest[:]), nil
}

// sign returns a compact ES256 JWS over claims, with the public key in the jwk header.
func sign(key *ecdsa.PrivateKey, typ string, claims map[string]any) (string, error) {
	jwk, err := publicJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}
	header := map[string]any{
		"typ": typ,
		"alg": "ES256",
		"jwk": jwk,
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig), nil
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b64(b)
}

func pretty(raw []byte) string {
	var out bytes.Buffer
	if json.Indent(&out, raw, "", "  ") != nil {
		return string(raw)
	}
	return out.String()
}
