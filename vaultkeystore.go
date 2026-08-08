package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"github.com/snowmerak/hmacsecret/lib/store"
	"golang.org/x/crypto/chacha20poly1305"
	_ "modernc.org/sqlite"
)

const (
	vaultKeyEnvelopeVersion   = 1
	vaultKeyEnvelopeAlgorithm = "XChaCha20-Poly1305"
)

var errVaultKeyEnvelopeNotFound = errors.New("vault key envelope not found")

// vaultKeyEnvelopeStore keeps the random vault DEK wrapped by the current
// root KEK. Envelopes are versioned by encrypted-store header revision so a
// new wrapper can be staged safely before an atomic KEK header rotation.
type vaultKeyEnvelopeStore struct {
	db *sql.DB
}

func openVaultKeyEnvelopeStore(path string) (*vaultKeyEnvelopeStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open vault key envelope store: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &vaultKeyEnvelopeStore{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *vaultKeyEnvelopeStore) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS vault_key_envelopes (
	header_revision INTEGER PRIMARY KEY NOT NULL,
	version INTEGER NOT NULL,
	algorithm TEXT NOT NULL,
	credential_id BLOB NOT NULL,
	salt BLOB NOT NULL,
	rp_id TEXT NOT NULL,
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL
);`)
	if err != nil {
		return fmt.Errorf("migrate vault key envelope store: %w", err)
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) put(
	ctx context.Context,
	headerRevision uint64,
	ref store.KEKReference,
	vaultDEK, kek *memguard.Enclave,
) error {
	nonce, ciphertext, err := sealVaultKey(vaultDEK, kek, vaultKeyEnvelopeAAD(headerRevision, ref))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO vault_key_envelopes (
	header_revision, version, algorithm, credential_id, salt, rp_id, nonce, ciphertext
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(header_revision) DO UPDATE SET
	version = excluded.version,
	algorithm = excluded.algorithm,
	credential_id = excluded.credential_id,
	salt = excluded.salt,
	rp_id = excluded.rp_id,
	nonce = excluded.nonce,
	ciphertext = excluded.ciphertext`,
		headerRevision,
		vaultKeyEnvelopeVersion,
		vaultKeyEnvelopeAlgorithm,
		ref.CredentialID,
		ref.Salt,
		ref.RPID,
		nonce,
		ciphertext,
	)
	if err != nil {
		return fmt.Errorf("store wrapped vault key: %w", err)
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) get(
	ctx context.Context,
	headerRevision uint64,
	ref store.KEKReference,
	kek *memguard.Enclave,
) (*memguard.Enclave, error) {
	var (
		version      uint16
		algorithm    string
		credentialID []byte
		salt         []byte
		rpID         string
		nonce        []byte
		ciphertext   []byte
	)
	err := s.db.QueryRowContext(ctx, `
SELECT version, algorithm, credential_id, salt, rp_id, nonce, ciphertext
FROM vault_key_envelopes
WHERE header_revision = ?`, headerRevision).Scan(
		&version,
		&algorithm,
		&credentialID,
		&salt,
		&rpID,
		&nonce,
		&ciphertext,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errVaultKeyEnvelopeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load wrapped vault key: %w", err)
	}
	if version != vaultKeyEnvelopeVersion || algorithm != vaultKeyEnvelopeAlgorithm {
		return nil, errors.New("unsupported vault key envelope format")
	}
	if !bytes.Equal(credentialID, ref.CredentialID) ||
		!bytes.Equal(salt, ref.Salt) || rpID != ref.RPID {
		return nil, errors.New("vault key envelope does not match the KEK header")
	}
	return openVaultKey(kek, nonce, ciphertext, vaultKeyEnvelopeAAD(headerRevision, ref))
}

func (s *vaultKeyEnvelopeStore) delete(ctx context.Context, headerRevision uint64) error {
	if _, err := s.db.ExecContext(ctx, `
DELETE FROM vault_key_envelopes WHERE header_revision = ?`, headerRevision); err != nil {
		return fmt.Errorf("delete wrapped vault key: %w", err)
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) deleteExcept(ctx context.Context, headerRevision uint64) error {
	if _, err := s.db.ExecContext(ctx, `
DELETE FROM vault_key_envelopes WHERE header_revision <> ?`, headerRevision); err != nil {
		return fmt.Errorf("delete obsolete wrapped vault keys: %w", err)
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func randomVaultKey() (*memguard.Enclave, error) {
	buffer := memguard.NewBuffer(chacha20poly1305.KeySize)
	if buffer.Size() != chacha20poly1305.KeySize {
		buffer.Destroy()
		return nil, errors.New("allocate vault key buffer")
	}
	if _, err := io.ReadFull(rand.Reader, buffer.Bytes()); err != nil {
		buffer.Destroy()
		return nil, fmt.Errorf("generate vault key: %w", err)
	}
	return buffer.Seal(), nil
}

func sealVaultKey(vaultDEK, kek *memguard.Enclave, aad []byte) ([]byte, []byte, error) {
	aead, cleanup, err := vaultAEAD(kek)
	if err != nil {
		return nil, nil, fmt.Errorf("open vault KEK: %w", err)
	}
	defer cleanup()
	plaintext, err := vaultDEK.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("open vault DEK: %w", err)
	}
	defer plaintext.Destroy()
	if plaintext.Size() != chacha20poly1305.KeySize {
		return nil, nil, errors.New("invalid vault DEK size")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate vault key nonce: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext.Bytes(), aad), nil
}

func openVaultKey(kek *memguard.Enclave, nonce, ciphertext, aad []byte) (*memguard.Enclave, error) {
	aead, cleanup, err := vaultAEAD(kek)
	if err != nil {
		return nil, fmt.Errorf("open vault KEK: %w", err)
	}
	defer cleanup()
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid vault key nonce")
	}
	buffer := memguard.NewBuffer(chacha20poly1305.KeySize)
	if buffer.Size() != chacha20poly1305.KeySize {
		buffer.Destroy()
		return nil, errors.New("allocate vault key buffer")
	}
	plaintext, err := aead.Open(buffer.Bytes()[:0], nonce, ciphertext, aad)
	if err != nil {
		buffer.Destroy()
		return nil, errors.New("vault key authentication failed")
	}
	if len(plaintext) != chacha20poly1305.KeySize {
		buffer.Destroy()
		return nil, errors.New("invalid unwrapped vault key size")
	}
	return buffer.Seal(), nil
}

func vaultKeyEnvelopeAAD(headerRevision uint64, ref store.KEKReference) []byte {
	aad := append([]byte(nil), "hsec/vault-key-envelope/v1"...)
	var revision [8]byte
	binary.BigEndian.PutUint64(revision[:], headerRevision)
	aad = append(aad, revision[:]...)
	aad = appendVaultKeyAADField(aad, ref.CredentialID)
	aad = appendVaultKeyAADField(aad, ref.Salt)
	aad = appendVaultKeyAADField(aad, []byte(ref.RPID))
	return aad
}

func appendVaultKeyAADField(dst, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...)
}
