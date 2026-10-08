package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// File layout: magic | format version | KDF id | Argon2id time, memory (KiB),
// threads | salt | nonce | AES-256-GCM ciphertext (additional data: magic).
// The KDF parameters live in the header so they can be raised over time.
const (
	magic         = "SSHVLT2"
	formatVersion = 2
	kdfArgon2id   = 1
	saltLen       = 16
	keyLen        = 32
	nonceLen      = 12
	headerLen     = len(magic) + 1 + 1 + 4 + 4 + 1 + saltLen + nonceLen
	schemaVersion = 4
)

var (
	ErrWrongPassword = errors.New("wrong password or damaged vault")
	ErrNewerVault    = errors.New("vault was written by a newer version")
	ErrFormat        = errors.New("not a vault file or damaged")
)

type kdfParams struct {
	time, memory uint32 // memory in KiB
	threads      uint8
}

// defaultKDF is RFC 9106's second recommended Argon2id setting with four
// times the memory.
var defaultKDF = kdfParams{time: 3, memory: 256 * 1024, threads: 4}

// valid bounds parameters read from an untrusted header, so a damaged or
// crafted file cannot crash the process or exhaust memory.
func (p kdfParams) valid() bool {
	return p.time >= 1 && p.time <= 10 &&
		p.threads >= 1 && p.threads <= 64 &&
		p.memory >= 8*uint32(p.threads) && p.memory <= 4<<20
}

// weakerThan reports whether q is stronger than p in one dimension and weaker
// in none, so that upgrading to q never lowers memory or passes.
func (p kdfParams) weakerThan(q kdfParams) bool {
	return p.memory <= q.memory && p.time <= q.time && (p.memory < q.memory || p.time < q.time)
}

// deriveKey normalizes the password to NFC (RFC 8265), so that the same
// characters entered on different systems give the same key.
func deriveKey(password string, salt []byte, p kdfParams) []byte {
	return argon2.IDKey([]byte(norm.NFC.String(password)), salt, p.time, p.memory, p.threads, keyLen)
}

type header struct {
	kdf         kdfParams
	salt, nonce []byte
}

// parse splits a vault file into its validated header and the ciphertext.
func parse(b []byte) (header, []byte, error) {
	if len(b) <= headerLen || string(b[:len(magic)]) != magic {
		return header{}, nil, ErrFormat
	}
	b = b[len(magic):]
	switch {
	case b[0] > formatVersion:
		return header{}, nil, ErrNewerVault
	case b[0] != formatVersion || b[1] != kdfArgon2id:
		return header{}, nil, ErrFormat
	}
	h := header{
		kdf: kdfParams{
			time:    binary.BigEndian.Uint32(b[2:6]),
			memory:  binary.BigEndian.Uint32(b[6:10]),
			threads: b[10],
		},
		salt:  b[11 : 11+saltLen],
		nonce: b[11+saltLen : 11+saltLen+nonceLen],
	}
	if !h.kdf.valid() {
		return header{}, nil, ErrFormat
	}
	return h, b[11+saltLen+nonceLen:], nil
}

// seal encrypts plain with a fresh random nonce and returns the complete file.
func seal(key, salt []byte, p kdfParams, plain []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	rand.Read(nonce)
	out := make([]byte, 0, headerLen+len(plain)+aead.Overhead())
	out = append(out, magic...)
	out = append(out, formatVersion, kdfArgon2id)
	out = binary.BigEndian.AppendUint32(out, p.time)
	out = binary.BigEndian.AppendUint32(out, p.memory)
	out = append(out, p.threads)
	out = append(out, salt...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, []byte(magic)), nil
}

func decrypt(key []byte, h header, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, h.nonce, ciphertext, []byte(magic))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return plain, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
