package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maulai/vaultty/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var errDenied = errors.New("denied")

// serverOptions configures testServer.
type serverOptions struct {
	hostKeys    []ssh.Signer  // default: one new ed25519 key
	algorithms  ssh.Config    // offered algorithms; zero means x/crypto defaults
	key         ssh.PublicKey // accepted client key
	password    string        // accepted password
	interactive bool          // ask for the password via keyboard-interactive only
	otp         bool          // keyboard-interactive then asks for a one-time code
	silent      bool          // never answer global requests
	shell       bool          // accept sessions; see runShell
	hang        bool          // the shell never exits
	echo        bool          // the shell echoes its input until EOF before it exits
	exitStatus  uint32        // exit status of the shell
}

// testServer is an in-process SSH server that counts authentication attempts
// of any method, including "none".
type testServer struct {
	host     vault.Host
	known    []vault.KnownHost // trusts the server's first host key
	attempts atomic.Int32
	codes    atomic.Int32 // answers to the one-time code prompt
}

func listen(t *testing.T) (net.Listener, vault.Host) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return ln, vault.Host{Name: "test", Hostname: host, Port: p, User: "u"}
}

func ed25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func startServer(t *testing.T, opts serverOptions) *testServer {
	t.Helper()
	if len(opts.hostKeys) == 0 {
		opts.hostKeys = []ssh.Signer{ed25519Signer(t)}
	}

	srv := &testServer{}
	cfg := &ssh.ServerConfig{
		Config:          opts.algorithms,
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { srv.attempts.Add(1) },
	}
	for _, k := range opts.hostKeys {
		cfg.AddHostKey(k)
	}
	if opts.key != nil {
		cfg.PublicKeyCallback = func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(k.Marshal(), opts.key.Marshal()) {
				return nil, nil
			}
			return nil, errDenied
		}
	}
	switch {
	case opts.password != "" && opts.interactive:
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("", "", []string{"Password: ", "Name: "}, []bool{false, true})
			if err != nil {
				return nil, err
			}
			if len(answers) != 2 || answers[0] != opts.password || answers[1] != "" {
				return nil, errDenied
			}
			if opts.otp {
				if _, err := challenge("", "", []string{"Verification code: "}, []bool{false}); err == nil {
					srv.codes.Add(1)
				}
				return nil, errDenied
			}
			return nil, nil
		}
	case opts.password != "":
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == opts.password {
				return nil, nil
			}
			return nil, errDenied
		}
	}

	ln, host := listen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, cfg, opts)
		}
	}()

	srv.host = host
	addr := net.JoinHostPort(host.Hostname, strconv.Itoa(host.Port))
	srv.known = []vault.KnownHost{{Host: knownhosts.Normalize(addr), Key: authorized(opts.hostKeys[0].PublicKey())}}
	return srv
}

func serve(conn net.Conn, cfg *ssh.ServerConfig, opts serverOptions) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sc.Close()
	if !opts.silent {
		go ssh.DiscardRequests(reqs)
	}
	for nc := range chans {
		if !opts.shell || nc.ChannelType() != "session" {
			nc.Reject(ssh.Prohibited, "no channels")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			return
		}
		go runShell(ch, reqs, opts)
	}
}

// runShell grants pty and shell requests; the shell prints one line and exits
// unless opts.hang is set.
func runShell(ch ssh.Channel, reqs <-chan *ssh.Request, opts serverOptions) {
	defer ch.Close()
	for req := range reqs {
		req.Reply(req.Type == "pty-req" || req.Type == "shell", nil)
		if req.Type == "shell" {
			io.WriteString(ch, "hello\r\n")
			if opts.echo {
				io.Copy(ch, ch)
			}
			if !opts.hang {
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{opts.exitStatus}))
				return
			}
		}
	}
}

func TestDialTrustOnFirstUse(t *testing.T) {
	keyPEM, clientPub := testKey(t, "pp")
	_, otherPub := testKey(t, "")
	for _, auth := range []string{vault.AuthKey, vault.AuthPassword} {
		t.Run(auth, func(t *testing.T) {
			srv := startServer(t, serverOptions{key: clientPub, password: "pw"})
			host := srv.host
			host.Auth, host.Password = auth, "pw"
			wantHost := "[127.0.0.1]:" + strconv.Itoa(host.Port)

			// Unknown host: abort before any credentials are sent.
			_, err := Dial(t.Context(), host, keyPEM, "pp", nil)
			var herr *HostKeyError
			if !errors.As(err, &herr) {
				t.Fatalf("unknown host: err = %v, want *HostKeyError", err)
			}
			if herr.Changed() || herr.Host != wantHost || herr.Key != srv.known[0].Key {
				t.Fatalf("unknown host: got %+v, want host %q", *herr, wantHost)
			}

			// Changed: another key is trusted for the host; abort again.
			_, err = Dial(t.Context(), host, keyPEM, "pp", []vault.KnownHost{{Host: wantHost, Key: authorized(otherPub)}})
			if !errors.As(err, &herr) || !herr.Changed() {
				t.Fatalf("changed: err = %v, want changed *HostKeyError", err)
			}
			if !slices.Equal(herr.Trusted, []string{ssh.FingerprintSHA256(otherPub)}) {
				t.Fatalf("changed: Trusted = %v", herr.Trusted)
			}
			if n := srv.attempts.Load(); n != 0 {
				t.Fatalf("%d auth attempts before trust, want 0", n)
			}

			// Trusted: log in; the key carries a passphrase.
			s, err := Dial(t.Context(), host, keyPEM, "pp", []vault.KnownHost{{Host: herr.Host, Key: herr.Key}})
			if err != nil {
				t.Fatalf("trusted: %v", err)
			}
			s.Close()
			if srv.attempts.Load() == 0 {
				t.Fatal("trusted: no auth attempt counted")
			}
		})
	}
}

func TestDialHostKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ed := ed25519Signer(t)
	_, otherPub := testKey(t, "")

	tests := []struct {
		name     string
		hostKeys []ssh.Signer
		trusted  ssh.PublicKey
		wantErr  bool
	}{
		// The server prefers ed25519 but must present the trusted RSA key.
		{"trusted type preferred", []ssh.Signer{ed, rsaSigner}, rsaSigner.PublicKey(), false},
		// The server no longer has the trusted type: report a changed key.
		{"trusted type gone", []ssh.Signer{rsaSigner}, otherPub, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, serverOptions{hostKeys: tt.hostKeys, password: "pw"})
			host := srv.host
			host.Auth, host.Password = vault.AuthPassword, "pw"
			known := []vault.KnownHost{{Host: srv.known[0].Host, Key: authorized(tt.trusted)}}
			s, err := Dial(t.Context(), host, nil, "", known)
			if !tt.wantErr {
				if err != nil {
					t.Fatal(err)
				}
				s.Close()
				return
			}
			var herr *HostKeyError
			if !errors.As(err, &herr) || !herr.Changed() {
				t.Fatalf("err = %v, want changed *HostKeyError", err)
			}
			if herr.Key != authorized(rsaSigner.PublicKey()) {
				t.Fatalf("offered key = %q, want the server's RSA key", herr.Key)
			}
			if n := srv.attempts.Load(); n != 0 {
				t.Fatalf("%d auth attempts, want 0", n)
			}
		})
	}
}

func TestDialAuth(t *testing.T) {
	keyPEM, clientPub := testKey(t, "pp")
	wrongPEM, _ := testKey(t, "")
	tests := []struct {
		name        string
		auth        string
		key         []byte
		password    string
		interactive bool
		wantErr     error
	}{
		{"key", vault.AuthKey, keyPEM, "", false, nil},
		{"wrong key", vault.AuthKey, wrongPEM, "", false, ErrAuthFailed},
		{"no key", vault.AuthKey, nil, "", false, ErrNotPrivateKey},
		{"password", vault.AuthPassword, nil, "hunter2", false, nil},
		{"wrong password", vault.AuthPassword, nil, "nope", false, ErrAuthFailed},
		{"keyboard-interactive", vault.AuthPassword, nil, "hunter2", true, nil},
		{"wrong keyboard-interactive", vault.AuthPassword, nil, "nope", true, ErrAuthFailed},
		{"unknown method", "telepathy", nil, "", false, ErrUnknownAuth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, serverOptions{key: clientPub, password: "hunter2", interactive: tt.interactive})
			host := srv.host
			host.Auth, host.Password = tt.auth, tt.password
			s, err := Dial(t.Context(), host, tt.key, "pp", srv.known)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil {
				s.Close()
			}
		})
	}
}

// TestDialOneTimeCode checks that the stored password never answers a second
// hidden prompt, such as a one-time code.
func TestDialOneTimeCode(t *testing.T) {
	srv := startServer(t, serverOptions{password: "hunter2", interactive: true, otp: true})
	host := srv.host
	host.Auth, host.Password = vault.AuthPassword, "hunter2"
	if _, err := Dial(t.Context(), host, nil, "", srv.known); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
	if n := srv.codes.Load(); n != 0 {
		t.Fatalf("the code prompt got %d answers, want 0", n)
	}
}

func TestDialAlgorithms(t *testing.T) {
	tests := []struct {
		name    string
		server  ssh.Config
		wantErr bool
	}{
		{"sha1 key exchange", ssh.Config{KeyExchanges: []string{ssh.InsecureKeyExchangeDH14SHA1}}, true},
		{"sha1 mac", ssh.Config{Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.HMACSHA1}}, true},
		{"truncated mac", ssh.Config{Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.InsecureHMACSHA196}}, true},
		{"post-quantum hybrid", ssh.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519}}, false},
		{"ctr with sha2 etm", ssh.Config{Ciphers: []string{ssh.CipherAES256CTR}, MACs: []string{ssh.HMACSHA256ETM}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, serverOptions{algorithms: tt.server, password: "pw"})
			host := srv.host
			host.Auth, host.Password = vault.AuthPassword, "pw"
			s, err := Dial(t.Context(), host, nil, "", srv.known)
			if tt.wantErr {
				if err == nil {
					s.Close()
					t.Fatal("connected with a weak algorithm")
				}
				if n := srv.attempts.Load(); n != 0 {
					t.Fatalf("%d auth attempts, want 0", n)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
		})
	}
}

func TestDialHandshakeTimeout(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = old })

	// The kernel completes the TCP handshake, but nobody ever speaks SSH.
	_, host := listen(t)
	host.Auth = vault.AuthPassword
	start := time.Now()
	_, err := Dial(t.Context(), host, nil, "", nil)
	if !errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Dial took %v", d)
	}
}

func TestDialCancel(t *testing.T) {
	tests := []struct {
		name  string
		after time.Duration // cancel delay; negative cancels before Dial
	}{
		{"before connect", -1},
		{"during handshake", 100 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Nobody ever speaks SSH, so only the cancellation ends Dial.
			_, host := listen(t)
			host.Auth = vault.AuthPassword
			ctx, cancel := context.WithCancel(t.Context())
			if tt.after < 0 {
				cancel()
			} else {
				time.AfterFunc(tt.after, cancel)
			}
			start := time.Now()
			_, err := Dial(ctx, host, nil, "", nil)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("Dial took %v", d)
			}
		})
	}
}
