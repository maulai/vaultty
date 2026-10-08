package sshclient

import (
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

var (
	ErrNotPrivateKey      = errors.New("not a private key")
	ErrPassphraseRequired = errors.New("key requires a passphrase")
	ErrWrongPassphrase    = errors.New("wrong key passphrase")
)

// KeyInfo describes the public half of a private key.
type KeyInfo struct {
	Type        string // e.g. "ssh-ed25519"
	Fingerprint string // "SHA256:..."
}

// Inspect parses a PEM encoded private key and describes its public key.
func Inspect(key []byte, passphrase string) (KeyInfo, error) {
	signer, err := parseKey(key, passphrase)
	if err != nil {
		return KeyInfo{}, err
	}
	pub := signer.PublicKey()
	return KeyInfo{Type: pub.Type(), Fingerprint: ssh.FingerprintSHA256(pub)}, nil
}

// parseKey uses passphrase only for encrypted keys, so a superfluous
// passphrase on a plain key does no harm.
func parseKey(key []byte, passphrase string) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(key)
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		if passphrase == "" {
			return nil, ErrPassphraseRequired
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
		if errors.Is(err, x509.IncorrectPasswordError) {
			return nil, ErrWrongPassphrase
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotPrivateKey, err)
	}
	return signer, nil
}
