package sshclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/maulai/vaultty/internal/vault"
	"golang.org/x/crypto/ssh"
)

func authorized(k ssh.PublicKey) string {
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(k)), "\n")
}

func TestHostKeyAlgorithms(t *testing.T) {
	_, ed := testKey(t, "")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ssh.NewPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		trusted []ssh.PublicKey
		want    []string
	}{
		{"unknown host", nil, defaultHostKeyAlgorithms},
		{"ed25519", []ssh.PublicKey{ed}, defaultHostKeyAlgorithms},
		{"rsa uses sha2 signatures", []ssh.PublicKey{rs}, []string{
			ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		}},
		{"several keys", []ssh.PublicKey{ed, ec, rs, ed}, []string{
			ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostKeyAlgorithms(tt.trusted); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHostKeyCallback(t *testing.T) {
	_, offered := testKey(t, "")
	_, other := testKey(t, "")
	const host = "[example.com]:2222"

	tests := []struct {
		name    string
		known   []vault.KnownHost
		ok      bool
		trusted []string
	}{
		{"trusted", []vault.KnownHost{{Host: host, Key: authorized(offered)}}, true, nil},
		{"one of several trusted", []vault.KnownHost{{Host: host, Key: authorized(other)}, {Host: host, Key: authorized(offered)}}, true, nil},
		{"host name case differs", []vault.KnownHost{{Host: "[Example.COM]:2222", Key: authorized(offered)}}, true, nil},
		{"unknown host", nil, false, nil},
		{"trusted for another host only", []vault.KnownHost{{Host: "example.com", Key: authorized(offered)}}, false, nil},
		{"changed", []vault.KnownHost{{Host: host, Key: authorized(other)}}, false, []string{ssh.FingerprintSHA256(other)}},
		{"unparseable entry", []vault.KnownHost{{Host: host, Key: "garbage"}}, false, []string{invalidKey}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hostKeyCallback(tt.known)("example.com:2222", nil, offered)
			if tt.ok {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			var herr *HostKeyError
			if !errors.As(err, &herr) {
				t.Fatalf("err = %v, want *HostKeyError", err)
			}
			want := HostKeyError{Host: host, Key: authorized(offered), Fingerprint: ssh.FingerprintSHA256(offered), Trusted: tt.trusted}
			if herr.Host != want.Host || herr.Key != want.Key || herr.Fingerprint != want.Fingerprint || !slices.Equal(herr.Trusted, want.Trusted) {
				t.Fatalf("got %+v, want %+v", *herr, want)
			}
			if herr.Changed() != (len(tt.trusted) > 0) {
				t.Fatalf("Changed() = %v", herr.Changed())
			}
		})
	}
}
