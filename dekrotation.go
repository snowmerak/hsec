package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/awnumar/memguard"
)

const (
	vaultValueFilename       = "vault.sqlite"
	vaultValueShadowFilename = "vault.sqlite.dek-rotation-new"
	vaultValueBackupFilename = "vault.sqlite.dek-rotation-old"
)

type dekRotationProgress struct {
	Phase     string `json:"phase"`
	Completed int64  `json:"completed"`
	Total     int64  `json:"total"`
	Percent   int    `json:"percent"`
	Message   string `json:"message"`
}

// RotateDEK generates a new random vault DEK and re-encrypts every value into
// a shadow database. The old database remains untouched until the shadow is
// complete and its wrapped DEK has been staged in keys.sqlite.
func (s *VaultService) RotateDEK(ctx context.Context) (vaultStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.metadata == nil || s.values == nil || s.vaultKeys == nil {
		return vaultStatus{}, errors.New("select a vault before rotating its DEK")
	}
	if s.vaultDEK == nil || s.rootKEK == nil || s.activeSlotID == "" {
		return vaultStatus{}, errors.New("vault is locked")
	}
	slot, err := s.vaultKeys.credentialSlot(ctx, s.activeSlotID)
	if err != nil {
		return vaultStatus{}, fmt.Errorf("load active credential slot before DEK rotation: %w", err)
	}
	staged, err := s.vaultKeys.hasStagedCredentialSlotDEKRotation(ctx)
	if err != nil {
		return vaultStatus{}, err
	}
	legacyStaged, err := s.vaultKeys.hasStagedDEKRotation(ctx)
	if err != nil {
		return vaultStatus{}, err
	}
	if staged || legacyStaged {
		return vaultStatus{}, errors.New("an interrupted DEK rotation must be recovered by reopening the vault")
	}

	dataDir := s.selected.Path
	shadowPath := filepath.Join(dataDir, vaultValueShadowFilename)
	backupPath := filepath.Join(dataDir, vaultValueBackupFilename)
	if err := removeFileIfExists(shadowPath); err != nil {
		return vaultStatus{}, err
	}
	if err := removeFileIfExists(backupPath); err != nil {
		return vaultStatus{}, err
	}

	newDEK, err := randomVaultKey()
	if err != nil {
		return vaultStatus{}, err
	}
	total, err := s.values.count(ctx)
	if err != nil {
		return vaultStatus{}, err
	}
	s.emitDEKRotationProgress("copying", 0, total, "새 DEK로 항목을 다시 암호화하고 있습니다.")

	shadow, err := openVaultValueStore(shadowPath)
	if err != nil {
		return vaultStatus{}, fmt.Errorf("create DEK rotation database: %w", err)
	}
	copyErr := copyVaultValues(ctx, s.values, shadow, s.vaultDEK, newDEK, func(completed int64) {
		s.emitDEKRotationProgress("copying", completed, total, "새 DEK로 항목을 다시 암호화하고 있습니다.")
	})
	closeErr := shadow.close()
	if copyErr != nil || closeErr != nil {
		_ = removeFileIfExists(shadowPath)
		return vaultStatus{}, errors.Join(copyErr, closeErr)
	}
	_ = os.Chmod(shadowPath, 0o600)

	if err := s.vaultKeys.stageCredentialSlotDEKRotation(ctx, slot, newDEK, s.rootKEK); err != nil {
		_ = removeFileIfExists(shadowPath)
		return vaultStatus{}, err
	}
	if err := ctx.Err(); err != nil {
		_ = s.vaultKeys.clearStagedCredentialSlotDEKRotation(context.Background())
		_ = removeFileIfExists(shadowPath)
		return vaultStatus{}, err
	}

	s.emitDEKRotationProgress("switching", total, total, "완성된 데이터베이스로 전환하고 있습니다.")
	if err := s.values.close(); err != nil {
		s.values = nil
		_ = s.vaultKeys.clearStagedCredentialSlotDEKRotation(context.Background())
		_ = removeFileIfExists(shadowPath)
		reopenErr := s.reopenVaultValuesAfterRotationFailure(dataDir)
		return vaultStatus{}, errors.Join(fmt.Errorf("close current vault database: %w", err), reopenErr)
	}
	s.values = nil

	if err := swapVaultValueFiles(dataDir); err != nil {
		_ = s.vaultKeys.clearStagedCredentialSlotDEKRotation(context.Background())
		recoveryErr := recoverUncommittedDEKSwap(dataDir)
		reopenErr := s.reopenVaultValuesAfterRotationFailure(dataDir)
		return vaultStatus{}, errors.Join(err, recoveryErr, reopenErr)
	}

	if err := s.vaultKeys.promoteStagedCredentialSlotDEKRotation(context.Background()); err != nil {
		rollbackErr := rollbackVaultValueSwap(dataDir)
		var reopenErr error
		if rollbackErr == nil {
			_ = s.vaultKeys.clearStagedCredentialSlotDEKRotation(context.Background())
			reopenErr = s.reopenVaultValuesAfterRotationFailure(dataDir)
		} else {
			s.lockLocked()
		}
		return vaultStatus{}, errors.Join(fmt.Errorf("commit rotated vault DEK: %w", err), rollbackErr, reopenErr)
	}

	values, err := openVaultValueStore(filepath.Join(dataDir, vaultValueFilename))
	if err != nil {
		s.lockLocked()
		return vaultStatus{}, fmt.Errorf("open rotated vault database: %w", err)
	}
	s.values = values
	s.vaultDEK = newDEK
	_ = removeFileIfExists(backupPath)
	s.emitDEKRotationProgress("completed", total, total, "DEK 회전이 완료되었습니다.")
	return s.statusLocked(ctx)
}

func (s *VaultService) reopenVaultValuesAfterRotationFailure(dataDir string) error {
	values, err := openVaultValueStore(filepath.Join(dataDir, vaultValueFilename))
	if err != nil {
		s.lockLocked()
		return fmt.Errorf("reopen original vault database: %w", err)
	}
	s.values = values
	return nil
}

func copyVaultValues(
	ctx context.Context,
	source, destination *vaultValueStore,
	oldDEK, newDEK *memguard.Enclave,
	progress func(int64),
) error {
	rows, err := source.db.QueryContext(ctx, `
SELECT alias, revision, nonce, ciphertext, created_at, updated_at
FROM vault_entries
ORDER BY alias COLLATE BINARY`)
	if err != nil {
		return fmt.Errorf("read vault entries for DEK rotation: %w", err)
	}
	defer rows.Close()

	tx, err := destination.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin DEK rotation copy: %w", err)
	}
	defer tx.Rollback()
	statement, err := tx.PrepareContext(ctx, `
INSERT INTO vault_entries (alias, revision, nonce, ciphertext, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare DEK rotation copy: %w", err)
	}
	defer statement.Close()

	var completed int64
	lastProgress := time.Now()
	for rows.Next() {
		var (
			alias                string
			revision             uint64
			nonce, ciphertext    []byte
			createdAt, updatedAt string
		)
		if err := rows.Scan(&alias, &revision, &nonce, &ciphertext, &createdAt, &updatedAt); err != nil {
			return fmt.Errorf("scan vault entry for DEK rotation: %w", err)
		}
		plaintext, err := openVaultValue(oldDEK, alias, revision, nonce, ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt %q during DEK rotation: %w", alias, err)
		}
		nextNonce, nextCiphertext, sealErr := sealVaultValue(newDEK, alias, revision, plaintext)
		memguard.WipeBytes(plaintext)
		if sealErr != nil {
			return fmt.Errorf("encrypt %q during DEK rotation: %w", alias, sealErr)
		}
		if _, err := statement.ExecContext(ctx, alias, revision, nextNonce, nextCiphertext, createdAt, updatedAt); err != nil {
			return fmt.Errorf("write %q during DEK rotation: %w", alias, err)
		}
		completed++
		if progress != nil && (time.Since(lastProgress) >= 100*time.Millisecond) {
			progress(completed)
			lastProgress = time.Now()
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate vault entries for DEK rotation: %w", err)
	}
	if err := statement.Close(); err != nil {
		return fmt.Errorf("finish DEK rotation writes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit DEK rotation database: %w", err)
	}
	if progress != nil {
		progress(completed)
	}

	var copied int64
	if err := destination.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_entries`).Scan(&copied); err != nil {
		return fmt.Errorf("verify DEK rotation entry count: %w", err)
	}
	if copied != completed {
		return fmt.Errorf("verify DEK rotation entry count: copied %d, expected %d", copied, completed)
	}
	var integrity string
	if err := destination.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("check rotated vault database: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("rotated vault database integrity check failed: %s", integrity)
	}
	return nil
}

func (s *VaultService) emitDEKRotationProgress(phase string, completed, total int64, message string) {
	percent := 0
	if total == 0 || completed >= total {
		percent = 100
	} else if completed > 0 {
		percent = int(completed * 100 / total)
	}
	s.emit("vault:dek-rotation-progress", dekRotationProgress{
		Phase:     phase,
		Completed: completed,
		Total:     total,
		Percent:   percent,
		Message:   message,
	})
}

func recoverDEKRotationFiles(dataDir string, keys *vaultKeyEnvelopeStore) error {
	ctx := context.Background()
	livePath := filepath.Join(dataDir, vaultValueFilename)
	shadowPath := filepath.Join(dataDir, vaultValueShadowFilename)
	backupPath := filepath.Join(dataDir, vaultValueBackupFilename)
	live, shadow, backup := fileExists(livePath), fileExists(shadowPath), fileExists(backupPath)
	slotStaged, err := keys.hasStagedCredentialSlotDEKRotation(ctx)
	if err != nil {
		return err
	}
	legacyStaged, err := keys.hasStagedDEKRotation(ctx)
	if err != nil {
		return err
	}
	if slotStaged && legacyStaged {
		return errors.New("vault has conflicting interrupted DEK rotations")
	}
	staged := slotStaged || legacyStaged
	promote := keys.promoteStagedCredentialSlotDEKRotation
	clear := keys.clearStagedCredentialSlotDEKRotation
	if legacyStaged {
		promote = keys.promoteStagedDEKRotation
		clear = keys.clearStagedDEKRotation
	}

	if !staged {
		if !live && !shadow && !backup {
			// A newly selected, empty directory has no value database yet.
			return nil
		}
		if !live && backup {
			if err := os.Rename(backupPath, livePath); err != nil {
				return fmt.Errorf("restore vault database after interrupted DEK rotation: %w", err)
			}
			live, backup = true, false
		}
		if !live {
			return errors.New("vault database is missing")
		}
		if shadow {
			_ = removeFileIfExists(shadowPath)
		}
		if backup {
			_ = removeFileIfExists(backupPath)
		}
		return nil
	}

	switch {
	case live && backup && !shadow:
		// Both file renames completed. Committing the staged wrapper makes the
		// already-complete shadow database authoritative.
		if err := promote(ctx); err != nil {
			return err
		}
		_ = removeFileIfExists(backupPath)
		return nil
	case !live && backup:
		// Only the first rename completed. Restore the untouched old database.
		if err := os.Rename(backupPath, livePath); err != nil {
			return fmt.Errorf("roll back interrupted DEK rotation: %w", err)
		}
		_ = removeFileIfExists(shadowPath)
		return clear(ctx)
	case live && !backup:
		// The swap did not start. The live database still uses the old DEK.
		_ = removeFileIfExists(shadowPath)
		return clear(ctx)
	default:
		return errors.New("vault has an unrecognized interrupted DEK rotation state")
	}
}

func swapVaultValueFiles(dataDir string) error {
	livePath := filepath.Join(dataDir, vaultValueFilename)
	shadowPath := filepath.Join(dataDir, vaultValueShadowFilename)
	backupPath := filepath.Join(dataDir, vaultValueBackupFilename)
	if err := os.Rename(livePath, backupPath); err != nil {
		return fmt.Errorf("preserve current vault database: %w", err)
	}
	if err := os.Rename(shadowPath, livePath); err != nil {
		rollbackErr := os.Rename(backupPath, livePath)
		return errors.Join(fmt.Errorf("activate rotated vault database: %w", err), rollbackErr)
	}
	return nil
}

func rollbackVaultValueSwap(dataDir string) error {
	livePath := filepath.Join(dataDir, vaultValueFilename)
	shadowPath := filepath.Join(dataDir, vaultValueShadowFilename)
	backupPath := filepath.Join(dataDir, vaultValueBackupFilename)
	if err := os.Rename(livePath, shadowPath); err != nil {
		return fmt.Errorf("preserve failed rotated database: %w", err)
	}
	if err := os.Rename(backupPath, livePath); err != nil {
		return fmt.Errorf("restore original vault database: %w", err)
	}
	_ = removeFileIfExists(shadowPath)
	return nil
}

func recoverUncommittedDEKSwap(dataDir string) error {
	livePath := filepath.Join(dataDir, vaultValueFilename)
	shadowPath := filepath.Join(dataDir, vaultValueShadowFilename)
	backupPath := filepath.Join(dataDir, vaultValueBackupFilename)
	if !fileExists(livePath) && fileExists(backupPath) {
		if err := os.Rename(backupPath, livePath); err != nil {
			return err
		}
	}
	_ = removeFileIfExists(shadowPath)
	return nil
}

func removeFileIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove %s: %w", filepath.Base(path), err)
	}
	return nil
}

func (s *vaultValueStore) count(ctx context.Context) (int64, error) {
	var count int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_entries`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count vault entries: %w", err)
	}
	return count, nil
}
