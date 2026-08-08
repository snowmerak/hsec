package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/awnumar/memguard"
	"github.com/snowmerak/hmacsecret/lib/store"
)

const maxCredentialSlotLabelBytes = 128

var (
	errCredentialSlotNotFound = errors.New("credential slot not found")
	errCredentialSlotLabel    = errors.New("credential slot label is already in use")
)

type CredentialSlotInfo struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt"`
	Active     bool   `json:"active"`
}

type credentialSlot struct {
	Info       CredentialSlotInfo
	Ref        store.KEKReference
	Version    uint16
	Algorithm  string
	Nonce      []byte
	Ciphertext []byte
}

func (s *vaultKeyEnvelopeStore) migrateCredentialSlots(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS credential_slots (
	slot_id TEXT PRIMARY KEY NOT NULL,
	label TEXT NOT NULL COLLATE NOCASE UNIQUE,
	credential_id BLOB NOT NULL,
	salt BLOB NOT NULL,
	rp_id TEXT NOT NULL,
	version INTEGER NOT NULL,
	algorithm TEXT NOT NULL,
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	created_at TEXT NOT NULL,
	last_used_at TEXT NOT NULL DEFAULT '',
	UNIQUE (rp_id, credential_id)
);
CREATE TABLE IF NOT EXISTS credential_slot_dek_rotation (
	id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
	slot_id TEXT NOT NULL,
	label TEXT NOT NULL,
	credential_id BLOB NOT NULL,
	salt BLOB NOT NULL,
	rp_id TEXT NOT NULL,
	version INTEGER NOT NULL,
	algorithm TEXT NOT NULL,
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	created_at TEXT NOT NULL,
	last_used_at TEXT NOT NULL
);`)
	if err != nil {
		return fmt.Errorf("migrate credential slots: %w", err)
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) createCredentialSlot(
	ctx context.Context,
	label string,
	ref store.KEKReference,
	vaultDEK, kek *memguard.Enclave,
) (CredentialSlotInfo, error) {
	label, err := validateCredentialSlotLabel(label)
	if err != nil {
		return CredentialSlotInfo{}, err
	}
	slotID, err := randomCredentialSlotID()
	if err != nil {
		return CredentialSlotInfo{}, err
	}
	nonce, ciphertext, err := sealVaultKey(vaultDEK, kek, credentialSlotAAD(slotID, ref))
	if err != nil {
		return CredentialSlotInfo{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO credential_slots (
	slot_id, label, credential_id, salt, rp_id, version, algorithm,
	nonce, ciphertext, created_at, last_used_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		slotID,
		label,
		ref.CredentialID,
		ref.Salt,
		ref.RPID,
		vaultKeyEnvelopeVersion,
		vaultKeyEnvelopeAlgorithm,
		nonce,
		ciphertext,
		now,
		now,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return CredentialSlotInfo{}, errCredentialSlotLabel
		}
		return CredentialSlotInfo{}, fmt.Errorf("create credential slot: %w", err)
	}
	return CredentialSlotInfo{ID: slotID, Label: label, CreatedAt: now, LastUsedAt: now}, nil
}

func (s *vaultKeyEnvelopeStore) credentialSlots(ctx context.Context) ([]CredentialSlotInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT slot_id, label, created_at, last_used_at
FROM credential_slots
ORDER BY CASE WHEN last_used_at = '' THEN 1 ELSE 0 END,
         last_used_at DESC,
         label COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list credential slots: %w", err)
	}
	defer rows.Close()
	result := make([]CredentialSlotInfo, 0)
	for rows.Next() {
		var info CredentialSlotInfo
		if err := rows.Scan(&info.ID, &info.Label, &info.CreatedAt, &info.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan credential slot: %w", err)
		}
		result = append(result, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list credential slots: %w", err)
	}
	return result, nil
}

func (s *vaultKeyEnvelopeStore) credentialSlot(ctx context.Context, slotID string) (credentialSlot, error) {
	slotID = strings.TrimSpace(slotID)
	if slotID == "" {
		return credentialSlot{}, errCredentialSlotNotFound
	}
	var slot credentialSlot
	slot.Info.ID = slotID
	err := s.db.QueryRowContext(ctx, `
SELECT label, credential_id, salt, rp_id, version, algorithm,
       nonce, ciphertext, created_at, last_used_at
FROM credential_slots
WHERE slot_id = ?`, slotID).Scan(
		&slot.Info.Label,
		&slot.Ref.CredentialID,
		&slot.Ref.Salt,
		&slot.Ref.RPID,
		&slot.Version,
		&slot.Algorithm,
		&slot.Nonce,
		&slot.Ciphertext,
		&slot.Info.CreatedAt,
		&slot.Info.LastUsedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return credentialSlot{}, errCredentialSlotNotFound
	}
	if err != nil {
		return credentialSlot{}, fmt.Errorf("load credential slot: %w", err)
	}
	if slot.Version != vaultKeyEnvelopeVersion || slot.Algorithm != vaultKeyEnvelopeAlgorithm {
		return credentialSlot{}, errors.New("unsupported credential slot format")
	}
	return slot, nil
}

func (s *vaultKeyEnvelopeStore) openCredentialSlot(
	ctx context.Context,
	slotID string,
	kek *memguard.Enclave,
) (*memguard.Enclave, CredentialSlotInfo, error) {
	slot, err := s.credentialSlot(ctx, slotID)
	if err != nil {
		return nil, CredentialSlotInfo{}, err
	}
	dek, err := openVaultKey(kek, slot.Nonce, slot.Ciphertext, credentialSlotAAD(slot.Info.ID, slot.Ref))
	if err != nil {
		return nil, CredentialSlotInfo{}, err
	}
	return dek, slot.Info, nil
}

func (s *vaultKeyEnvelopeStore) replaceCredentialSlot(
	ctx context.Context,
	slotID string,
	ref store.KEKReference,
	vaultDEK, kek *memguard.Enclave,
) error {
	slot, err := s.credentialSlot(ctx, slotID)
	if err != nil {
		return err
	}
	nonce, ciphertext, err := sealVaultKey(vaultDEK, kek, credentialSlotAAD(slotID, ref))
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE credential_slots
SET credential_id = ?, salt = ?, rp_id = ?, version = ?, algorithm = ?,
    nonce = ?, ciphertext = ?, last_used_at = ?
WHERE slot_id = ?`,
		ref.CredentialID,
		ref.Salt,
		ref.RPID,
		vaultKeyEnvelopeVersion,
		vaultKeyEnvelopeAlgorithm,
		nonce,
		ciphertext,
		time.Now().UTC().Format(time.RFC3339Nano),
		slot.Info.ID,
	)
	if err != nil {
		return fmt.Errorf("replace credential slot: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("replace credential slot: %w", err)
	}
	if affected != 1 {
		return errCredentialSlotNotFound
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) touchCredentialSlot(ctx context.Context, slotID string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE credential_slots SET last_used_at = ? WHERE slot_id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), slotID,
	)
	if err != nil {
		return fmt.Errorf("touch credential slot: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("touch credential slot: %w", err)
	}
	if affected != 1 {
		return errCredentialSlotNotFound
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) deleteCredentialSlot(ctx context.Context, slotID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM credential_slots WHERE slot_id = ?`, slotID)
	if err != nil {
		return fmt.Errorf("delete credential slot: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete credential slot: %w", err)
	}
	if affected != 1 {
		return errCredentialSlotNotFound
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) stageCredentialSlotDEKRotation(
	ctx context.Context,
	slot credentialSlot,
	newDEK, kek *memguard.Enclave,
) error {
	nonce, ciphertext, err := sealVaultKey(newDEK, kek, credentialSlotAAD(slot.Info.ID, slot.Ref))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO credential_slot_dek_rotation (
	id, slot_id, label, credential_id, salt, rp_id, version, algorithm,
	nonce, ciphertext, created_at, last_used_at
) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	slot_id = excluded.slot_id,
	label = excluded.label,
	credential_id = excluded.credential_id,
	salt = excluded.salt,
	rp_id = excluded.rp_id,
	version = excluded.version,
	algorithm = excluded.algorithm,
	nonce = excluded.nonce,
	ciphertext = excluded.ciphertext,
	created_at = excluded.created_at,
	last_used_at = excluded.last_used_at`,
		slot.Info.ID,
		slot.Info.Label,
		slot.Ref.CredentialID,
		slot.Ref.Salt,
		slot.Ref.RPID,
		vaultKeyEnvelopeVersion,
		vaultKeyEnvelopeAlgorithm,
		nonce,
		ciphertext,
		slot.Info.CreatedAt,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("stage credential-slot DEK rotation: %w", err)
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) hasStagedCredentialSlotDEKRotation(ctx context.Context) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM credential_slot_dek_rotation WHERE id = 1`).Scan(&count); err != nil {
		return false, fmt.Errorf("check credential-slot DEK rotation: %w", err)
	}
	return count == 1, nil
}

func (s *vaultKeyEnvelopeStore) promoteStagedCredentialSlotDEKRotation(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin credential-slot DEK rotation promotion: %w", err)
	}
	defer tx.Rollback()
	var slot credentialSlot
	err = tx.QueryRowContext(ctx, `
SELECT slot_id, label, credential_id, salt, rp_id, version, algorithm,
       nonce, ciphertext, created_at, last_used_at
FROM credential_slot_dek_rotation
WHERE id = 1`).Scan(
		&slot.Info.ID,
		&slot.Info.Label,
		&slot.Ref.CredentialID,
		&slot.Ref.Salt,
		&slot.Ref.RPID,
		&slot.Version,
		&slot.Algorithm,
		&slot.Nonce,
		&slot.Ciphertext,
		&slot.Info.CreatedAt,
		&slot.Info.LastUsedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return errCredentialSlotNotFound
	}
	if err != nil {
		return fmt.Errorf("load staged credential slot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM credential_slots`); err != nil {
		return fmt.Errorf("revoke old credential slots: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO credential_slots (
	slot_id, label, credential_id, salt, rp_id, version, algorithm,
	nonce, ciphertext, created_at, last_used_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		slot.Info.ID,
		slot.Info.Label,
		slot.Ref.CredentialID,
		slot.Ref.Salt,
		slot.Ref.RPID,
		slot.Version,
		slot.Algorithm,
		slot.Nonce,
		slot.Ciphertext,
		slot.Info.CreatedAt,
		slot.Info.LastUsedAt,
	); err != nil {
		return fmt.Errorf("promote credential slot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM credential_slot_dek_rotation WHERE id = 1`); err != nil {
		return fmt.Errorf("clear promoted credential-slot rotation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit credential-slot DEK rotation: %w", err)
	}
	return nil
}

func (s *vaultKeyEnvelopeStore) clearStagedCredentialSlotDEKRotation(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM credential_slot_dek_rotation WHERE id = 1`); err != nil {
		return fmt.Errorf("clear credential-slot DEK rotation: %w", err)
	}
	return nil
}

func credentialSlotAAD(slotID string, ref store.KEKReference) []byte {
	aad := append([]byte(nil), "hsec/credential-slot/v1"...)
	aad = appendCredentialSlotAADField(aad, []byte(slotID))
	aad = appendCredentialSlotAADField(aad, ref.CredentialID)
	aad = appendCredentialSlotAADField(aad, ref.Salt)
	aad = appendCredentialSlotAADField(aad, []byte(ref.RPID))
	return aad
}

func appendCredentialSlotAADField(dst, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...)
}

func validateCredentialSlotLabel(label string) (string, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return "", errors.New("credential slot label is required")
	}
	if !utf8.ValidString(label) || len(label) > maxCredentialSlotLabelBytes {
		return "", errors.New("credential slot label is invalid or too long")
	}
	return label, nil
}

func randomCredentialSlotID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate credential slot ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func defaultCredentialSlotLabel(device authenticatorInfo) string {
	product := strings.TrimSpace(device.Product)
	manufacturer := strings.TrimSpace(device.Manufacturer)
	switch {
	case device.WindowsHello && product != "":
		return product
	case product != "" && manufacturer != "" && !strings.Contains(strings.ToLower(product), strings.ToLower(manufacturer)):
		return manufacturer + " " + product
	case product != "":
		return product
	case manufacturer != "":
		return manufacturer + " FIDO2"
	default:
		return "FIDO2 보안 키"
	}
}
