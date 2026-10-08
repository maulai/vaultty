package sshclient

import (
	"bytes"
	"net"
	"slices"
	"strings"

	"github.com/maulai/vaultty/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const invalidKey = "invalid key"

// HostKeyError reports a host key that is not trusted for the host. Trusting
// it means storing Host and Key as a vault.KnownHost.
type HostKeyError struct {
	Host        string // known_hosts form: "example.com" or "[example.com]:2222"
	Key         string // offered key in authorized_keys format
	Fingerprint string // SHA256 fingerprint of the offered key
	// Trusted holds the fingerprints of the keys trusted so far, "invalid key"
	// for a stored key that cannot be parsed. It is empty for an unknown host.
	Trusted []string
}

// Changed reports whether the host already had a different trusted key.
func (e *HostKeyError) Changed() bool { return len(e.Trusted) > 0 }

func (e *HostKeyError) Error() string {
	if e.Changed() {
		return "host key for " + e.Host + " changed"
	}
	return "unknown host key for " + e.Host
}

// defaultHostKeyAlgorithms leaves out certificates, which are never trusted.
var defaultHostKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

// hostKeyAlgorithms prefers the types of the trusted keys, so a server holding
// several host keys presents the trusted one. The other types follow, so a
// server that dropped the trusted type still presents a key, which the host
// key callback then reports as changed.
func hostKeyAlgorithms(trusted []ssh.PublicKey) []string {
	var algos []string
	add := func(names ...string) {
		for _, n := range names {
			if !slices.Contains(algos, n) {
				algos = append(algos, n)
			}
		}
	}
	for _, k := range trusted {
		if k.Type() == ssh.KeyAlgoRSA {
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		} else {
			add(k.Type())
		}
	}
	add(defaultHostKeyAlgorithms...)
	return algos
}

// hostKeyCallback accepts only keys trusted for the dialed host. Any other key
// fails the handshake with a *HostKeyError before authentication starts.
func hostKeyCallback(known []vault.KnownHost) ssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		e := &HostKeyError{
			Host:        knownhosts.Normalize(hostname),
			Key:         strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n"),
			Fingerprint: ssh.FingerprintSHA256(key),
		}
		for _, k := range known {
			if !strings.EqualFold(k.Host, e.Host) {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Key))
			switch {
			case err != nil:
				e.Trusted = append(e.Trusted, invalidKey)
			case bytes.Equal(pub.Marshal(), key.Marshal()):
				return nil
			default:
				e.Trusted = append(e.Trusted, ssh.FingerprintSHA256(pub))
			}
		}
		return e
	}
}

// trustedKeys returns the parseable keys stored for host. Host names are
// matched case-insensitively, like DNS names.
func trustedKeys(known []vault.KnownHost, host string) []ssh.PublicKey {
	var keys []ssh.PublicKey
	for _, k := range known {
		if !strings.EqualFold(k.Host, host) {
			continue
		}
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Key)); err == nil {
			keys = append(keys, pub)
		}
	}
	return keys
}
