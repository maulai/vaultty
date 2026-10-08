package sshclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testKey returns a new ed25519 private key in OpenSSH PEM format, encrypted
// when passphrase is set, and its public key.
func testKey(t *testing.T, passphrase string) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), sshPub
}

func TestInspect(t *testing.T) {
	plain, plainPub := testKey(t, "")
	encrypted, encryptedPub := testKey(t, "secret")

	tests := []struct {
		name       string
		key        []byte
		passphrase string
		want       ssh.PublicKey
		wantErr    error
	}{
		{"plain", plain, "", plainPub, nil},
		{"superfluous passphrase", plain, "unused", plainPub, nil},
		{"passphrase missing", encrypted, "", nil, ErrPassphraseRequired},
		{"wrong passphrase", encrypted, "wrong", nil, ErrWrongPassphrase},
		{"correct passphrase", encrypted, "secret", encryptedPub, nil},
		{"public key", ssh.MarshalAuthorizedKey(plainPub), "", nil, ErrNotPrivateKey},
		{"empty", nil, "", nil, ErrNotPrivateKey},
		{"broken pem", []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), "", nil, ErrNotPrivateKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Inspect(tt.key, tt.passphrase)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.want == nil {
				return
			}
			want := KeyInfo{Type: ssh.KeyAlgoED25519, Fingerprint: ssh.FingerprintSHA256(tt.want)}
			if info != want {
				t.Fatalf("info = %+v, want %+v", info, want)
			}
		})
	}
}
