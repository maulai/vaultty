// Package sshclient connects to SSH hosts with trust-on-first-use host key
// checks and runs interactive sessions.
package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/maulai/vaultty/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	// ErrAuthFailed reports that the server rejected the credentials.
	ErrAuthFailed  = errors.New("authentication failed")
	ErrUnknownAuth = errors.New("unknown auth method")

	errMorePrompts = errors.New("server asks for more than the password")
)

// handshakeTimeout bounds the TCP connect and the SSH handshake including
// authentication together.
var handshakeTimeout = 15 * time.Second

// Dial connects to h and authenticates with its password or with key. The
// server's host key must be one of the keys trusted for h in known; otherwise
// Dial returns a *HostKeyError before any credentials are sent. Cancelling
// ctx aborts the attempt.
func Dial(ctx context.Context, h vault.Host, key []byte, passphrase string, known []vault.KnownHost) (*Session, error) {
	auth, err := authMethods(h, key, passphrase)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(h.Hostname, strconv.Itoa(h.Port))
	checkHostKey := hostKeyCallback(known)
	var hostKeyOK atomic.Bool
	cfg := &ssh.ClientConfig{
		Config: algorithms(),
		User:   h.User,
		Auth:   auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := checkHostKey(hostname, remote, key)
			hostKeyOK.Store(err == nil)
			return err
		},
		HostKeyAlgorithms: hostKeyAlgorithms(trustedKeys(known, knownhosts.Normalize(addr))),
	}

	deadline := time.Now().Add(handshakeTimeout)
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	// Cancelling ctx closes conn, which aborts the handshake. NewClientConn
	// closes conn when the handshake fails.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if !stop() { // ctx was cancelled
		if err == nil {
			c.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		// After the host key check only authentication is left, so an error
		// that does not come from the connection is the server's refusal.
		_, isNetErr := errors.AsType[net.Error](err)
		connErr := isNetErr || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		if hostKeyOK.Load() && !connErr {
			err = fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	return &Session{
		client:   ssh.NewClient(c, chans, reqs),
		password: h.Password,
		stdout:   os.Stdout,
		stderr:   os.Stdout,
	}, nil
}

// algorithms leaves out what x/crypto enables by default for old servers:
// SHA-1 key exchange and SHA-1 MACs.
func algorithms() ssh.Config {
	a := ssh.SupportedAlgorithms()
	return ssh.Config{
		KeyExchanges: a.KeyExchanges,
		Ciphers:      a.Ciphers,
		MACs:         slices.DeleteFunc(a.MACs, func(m string) bool { return m == ssh.HMACSHA1 }),
	}
}

func authMethods(h vault.Host, key []byte, passphrase string) ([]ssh.AuthMethod, error) {
	switch h.Auth {
	case vault.AuthPassword:
		// The password answers the first hidden prompt only. Another one, such
		// as a one-time code or a repeated password prompt, ends the attempt.
		answered := false
		answer := func(_, _ string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i, echo := range echos {
				if echo {
					continue
				}
				if answered {
					return nil, errMorePrompts
				}
				answered, answers[i] = true, h.Password
			}
			return answers, nil
		}
		return []ssh.AuthMethod{ssh.Password(h.Password), ssh.KeyboardInteractive(answer)}, nil
	case vault.AuthKey:
		signer, err := parseKey(key, passphrase)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownAuth, h.Auth)
}
