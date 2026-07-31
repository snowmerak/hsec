package main

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
	_ "modernc.org/sqlite"
)

const (
	vaultValueDocumentVersion = 1
	maxVaultValueFields       = 128
	maxVaultFieldNameBytes    = 1024
	maxVaultFieldValueBytes   = 1 << 20
)

var vaultValueDocumentPrefix = []byte("hsec/value-document/v1\n")

var (
	errAliasRequired = errors.New("alias is required")
	errEntryExists   = errors.New("entry already exists")
	errEntryNotFound = errors.New("entry not found")
	errEntryConflict = errors.New("entry was changed by another operation")
)

type vaultEntry struct {
	Alias     string             `json:"alias"`
	Value     vaultValueDocument `json:"value"`
	Revision  uint64             `json:"revision"`
	CreatedAt string             `json:"createdAt"`
	UpdatedAt string             `json:"updatedAt"`
}

type vaultValueDocument struct {
	Version uint16            `json:"version"`
	Fields  []vaultValueField `json:"fields"`
}

type vaultValueField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type vaultEntrySummary struct {
	Alias     string `json:"alias"`
	Revision  uint64 `json:"revision"`
	UpdatedAt string `json:"updatedAt"`
}

type vaultValueStore struct {
	db *sql.DB
}

func openVaultValueStore(path string) (*vaultValueStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open vault database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &vaultValueStore{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *vaultValueStore) migrate(ctx context.Context) error {
	const query = `
CREATE TABLE IF NOT EXISTS vault_entries (
	alias TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
	revision INTEGER NOT NULL,
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);`
	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("migrate vault database: %w", err)
	}
	return nil
}

func (s *vaultValueStore) close() error {
	return s.db.Close()
}

func (s *vaultValueStore) list(ctx context.Context) ([]vaultEntrySummary, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT alias, revision, updated_at
FROM vault_entries
ORDER BY alias COLLATE BINARY`)
	if err != nil {
		return nil, fmt.Errorf("list vault entries: %w", err)
	}
	defer rows.Close()

	entries := make([]vaultEntrySummary, 0)
	for rows.Next() {
		var entry vaultEntrySummary
		if err := rows.Scan(&entry.Alias, &entry.Revision, &entry.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan vault entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list vault entries: %w", err)
	}
	return entries, nil
}

func (s *vaultValueStore) get(ctx context.Context, alias string, key *memguard.Enclave) (vaultEntry, error) {
	if alias == "" {
		return vaultEntry{}, errAliasRequired
	}

	var entry vaultEntry
	var nonce, ciphertext []byte
	entry.Alias = alias
	err := s.db.QueryRowContext(ctx, `
SELECT revision, nonce, ciphertext, created_at, updated_at
FROM vault_entries
WHERE alias = ?`, alias,
	).Scan(&entry.Revision, &nonce, &ciphertext, &entry.CreatedAt, &entry.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return vaultEntry{}, errEntryNotFound
	}
	if err != nil {
		return vaultEntry{}, fmt.Errorf("get vault entry: %w", err)
	}

	plaintext, err := openVaultValue(key, alias, entry.Revision, nonce, ciphertext)
	if err != nil {
		return vaultEntry{}, err
	}
	defer memguard.WipeBytes(plaintext)
	entry.Value, err = decodeVaultValueDocument(plaintext)
	if err != nil {
		return vaultEntry{}, err
	}
	return entry, nil
}

func (s *vaultValueStore) create(ctx context.Context, alias string, value vaultValueDocument, key *memguard.Enclave) (vaultEntry, error) {
	if alias == "" {
		return vaultEntry{}, errAliasRequired
	}

	const revision uint64 = 1
	plaintext, value, err := encodeVaultValueDocument(value)
	if err != nil {
		return vaultEntry{}, err
	}
	defer memguard.WipeBytes(plaintext)
	nonce, ciphertext, err := sealVaultValue(key, alias, revision, plaintext)
	if err != nil {
		return vaultEntry{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO vault_entries (alias, revision, nonce, ciphertext, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`, alias, revision, nonce, ciphertext, now, now)
	if err != nil {
		if isUniqueConstraint(err) {
			return vaultEntry{}, errEntryExists
		}
		return vaultEntry{}, fmt.Errorf("create vault entry: %w", err)
	}
	return vaultEntry{Alias: alias, Value: value, Revision: revision, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *vaultValueStore) update(ctx context.Context, alias string, value vaultValueDocument, expectedRevision uint64, key *memguard.Enclave) (vaultEntry, error) {
	if alias == "" {
		return vaultEntry{}, errAliasRequired
	}
	if expectedRevision == 0 {
		return vaultEntry{}, errEntryConflict
	}

	nextRevision := expectedRevision + 1
	plaintext, value, err := encodeVaultValueDocument(value)
	if err != nil {
		return vaultEntry{}, err
	}
	defer memguard.WipeBytes(plaintext)
	nonce, ciphertext, err := sealVaultValue(key, alias, nextRevision, plaintext)
	if err != nil {
		return vaultEntry{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
UPDATE vault_entries
SET revision = ?, nonce = ?, ciphertext = ?, updated_at = ?
WHERE alias = ? AND revision = ?`,
		nextRevision, nonce, ciphertext, now, alias, expectedRevision,
	)
	if err != nil {
		return vaultEntry{}, fmt.Errorf("update vault entry: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return vaultEntry{}, fmt.Errorf("update vault entry: %w", err)
	}
	if affected == 0 {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM vault_entries WHERE alias = ?`, alias).Scan(&exists); err != nil {
			return vaultEntry{}, fmt.Errorf("check vault entry: %w", err)
		}
		if exists == 0 {
			return vaultEntry{}, errEntryNotFound
		}
		return vaultEntry{}, errEntryConflict
	}

	var createdAt string
	if err := s.db.QueryRowContext(ctx, `SELECT created_at FROM vault_entries WHERE alias = ?`, alias).Scan(&createdAt); err != nil {
		return vaultEntry{}, fmt.Errorf("reload vault entry: %w", err)
	}
	return vaultEntry{Alias: alias, Value: value, Revision: nextRevision, CreatedAt: createdAt, UpdatedAt: now}, nil
}

func encodeVaultValueDocument(value vaultValueDocument) ([]byte, vaultValueDocument, error) {
	value.Version = vaultValueDocumentVersion
	if value.Fields == nil {
		value.Fields = make([]vaultValueField, 0)
	}
	if err := validateVaultValueDocument(value); err != nil {
		return nil, vaultValueDocument{}, err
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, vaultValueDocument{}, fmt.Errorf("encode vault value: %w", err)
	}
	plaintext := make([]byte, 0, len(vaultValueDocumentPrefix)+len(body))
	plaintext = append(plaintext, vaultValueDocumentPrefix...)
	plaintext = append(plaintext, body...)
	memguard.WipeBytes(body)
	return plaintext, value, nil
}

func decodeVaultValueDocument(plaintext []byte) (vaultValueDocument, error) {
	if !bytes.HasPrefix(plaintext, vaultValueDocumentPrefix) {
		return vaultValueDocument{
			Version: vaultValueDocumentVersion,
			Fields: []vaultValueField{{
				Name:  "메모",
				Value: string(plaintext),
			}},
		}, nil
	}

	var value vaultValueDocument
	if err := json.Unmarshal(plaintext[len(vaultValueDocumentPrefix):], &value); err != nil {
		return vaultValueDocument{}, fmt.Errorf("decode vault value: %w", err)
	}
	if err := validateVaultValueDocument(value); err != nil {
		return vaultValueDocument{}, err
	}
	if value.Fields == nil {
		value.Fields = make([]vaultValueField, 0)
	}
	return value, nil
}

func validateVaultValueDocument(value vaultValueDocument) error {
	if value.Version != vaultValueDocumentVersion {
		return fmt.Errorf("unsupported vault value version: %d", value.Version)
	}
	if len(value.Fields) > maxVaultValueFields {
		return fmt.Errorf("vault value has too many fields: %d", len(value.Fields))
	}
	for index, field := range value.Fields {
		if field.Name == "" {
			return fmt.Errorf("vault value field %d has no name", index+1)
		}
		if len(field.Name) > maxVaultFieldNameBytes {
			return fmt.Errorf("vault value field %d name is too long", index+1)
		}
		if len(field.Value) > maxVaultFieldValueBytes {
			return fmt.Errorf("vault value field %d is too large", index+1)
		}
	}
	return nil
}

func (s *vaultValueStore) delete(ctx context.Context, alias string, expectedRevision uint64) error {
	if alias == "" {
		return errAliasRequired
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM vault_entries WHERE alias = ? AND revision = ?`, alias, expectedRevision)
	if err != nil {
		return fmt.Errorf("delete vault entry: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete vault entry: %w", err)
	}
	if affected == 0 {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM vault_entries WHERE alias = ?`, alias).Scan(&exists); err != nil {
			return fmt.Errorf("check vault entry: %w", err)
		}
		if exists == 0 {
			return errEntryNotFound
		}
		return errEntryConflict
	}
	return nil
}

func sealVaultValue(key *memguard.Enclave, alias string, revision uint64, plaintext []byte) ([]byte, []byte, error) {
	aead, cleanup, err := vaultAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate vault nonce: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext, vaultAAD(alias, revision)), nil
}

func openVaultValue(key *memguard.Enclave, alias string, revision uint64, nonce, ciphertext []byte) ([]byte, error) {
	aead, cleanup, err := vaultAEAD(key)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid vault nonce")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, vaultAAD(alias, revision))
	if err != nil {
		return nil, errors.New("vault entry authentication failed")
	}
	return plaintext, nil
}

func vaultAEAD(key *memguard.Enclave) (cipher.AEAD, func(), error) {
	if key == nil {
		return nil, nil, errors.New("vault is locked")
	}
	buffer, err := key.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("open vault key: %w", err)
	}
	cleanup := func() { buffer.Destroy() }
	if len(buffer.Bytes()) != chacha20poly1305.KeySize {
		cleanup()
		return nil, nil, errors.New("invalid vault key size")
	}
	aead, err := chacha20poly1305.NewX(buffer.Bytes())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create vault cipher: %w", err)
	}
	return aead, cleanup, nil
}

func vaultAAD(alias string, revision uint64) []byte {
	const prefix = "hsec/vault-entry/v1"
	aad := make([]byte, 0, len(prefix)+8+len(alias))
	aad = append(aad, prefix...)
	var encodedRevision [8]byte
	binary.BigEndian.PutUint64(encodedRevision[:], revision)
	aad = append(aad, encodedRevision[:]...)
	aad = append(aad, alias...)
	return aad
}

func isUniqueConstraint(err error) bool {
	message := err.Error()
	return containsFold(message, "unique") || containsFold(message, "constraint failed")
}

func containsFold(value, part string) bool {
	for i := 0; i+len(part) <= len(value); i++ {
		equal := true
		for j := range part {
			a, b := value[i+j], part[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if a != b {
				equal = false
				break
			}
		}
		if equal {
			return true
		}
	}
	return false
}
