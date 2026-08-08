package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var errVaultReferenceNotFound = errors.New("vault reference not found")

type vaultReference struct {
	Name                        string `json:"name"`
	Path                        string `json:"path"`
	LastOpenedAt                string `json:"lastOpenedAt"`
	Available                   bool   `json:"available"`
	PreferredDevicePath         string `json:"preferredDevicePath"`
	PreferredDeviceProduct      string `json:"preferredDeviceProduct"`
	PreferredDeviceManufacturer string `json:"preferredDeviceManufacturer"`
	PreferredDeviceVendorID     int16  `json:"preferredDeviceVendorId"`
	PreferredDeviceProductID    int16  `json:"preferredDeviceProductId"`
}

type vaultRegistry struct {
	db *sql.DB
}

func openVaultRegistry(path string) (*vaultRegistry, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open vault registry: %w", err)
	}
	db.SetMaxOpenConns(1)
	registry := &vaultRegistry{db: db}
	if err := registry.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return registry, nil
}

func (r *vaultRegistry) migrate(ctx context.Context) error {
	const query = `
CREATE TABLE IF NOT EXISTS vault_registry (
	path TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
	name TEXT NOT NULL,
	last_opened_at TEXT NOT NULL DEFAULT '',
	preferred_device_path TEXT NOT NULL DEFAULT '',
	preferred_device_product TEXT NOT NULL DEFAULT '',
	preferred_device_manufacturer TEXT NOT NULL DEFAULT '',
	preferred_device_vendor_id INTEGER NOT NULL DEFAULT 0,
	preferred_device_product_id INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS vault_registry_last_opened
ON vault_registry(last_opened_at DESC, name COLLATE BINARY);`
	if _, err := r.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("migrate vault registry: %w", err)
	}
	return nil
}

func (r *vaultRegistry) add(ctx context.Context, path string) (vaultReference, error) {
	normalized, err := normalizeVaultPath(path)
	if err != nil {
		return vaultReference{}, err
	}
	if err := validateVaultDirectory(normalized); err != nil {
		return vaultReference{}, err
	}
	// Resolve symlinks again after a new directory has been created. On macOS,
	// temporary paths commonly change from /var to /private/var at this point.
	normalized, err = normalizeVaultPath(normalized)
	if err != nil {
		return vaultReference{}, err
	}
	name := filepath.Base(normalized)
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = "vault"
	}
	_, err = r.db.ExecContext(ctx, `
INSERT INTO vault_registry(path, name)
VALUES (?, ?)
ON CONFLICT(path) DO UPDATE SET name = excluded.name`, normalized, name)
	if err != nil {
		return vaultReference{}, fmt.Errorf("register vault: %w", err)
	}
	return r.get(ctx, normalized)
}

func (r *vaultRegistry) get(ctx context.Context, path string) (vaultReference, error) {
	normalized, err := normalizeVaultPath(path)
	if err != nil {
		return vaultReference{}, err
	}
	var ref vaultReference
	err = r.db.QueryRowContext(ctx, `
SELECT name, path, last_opened_at,
       preferred_device_path, preferred_device_product, preferred_device_manufacturer,
       preferred_device_vendor_id, preferred_device_product_id
FROM vault_registry
WHERE path = ?`, normalized).Scan(
		&ref.Name,
		&ref.Path,
		&ref.LastOpenedAt,
		&ref.PreferredDevicePath,
		&ref.PreferredDeviceProduct,
		&ref.PreferredDeviceManufacturer,
		&ref.PreferredDeviceVendorID,
		&ref.PreferredDeviceProductID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return vaultReference{}, errVaultReferenceNotFound
	}
	if err != nil {
		return vaultReference{}, fmt.Errorf("load vault reference: %w", err)
	}
	ref.Available = vaultDirectoryAvailable(ref.Path)
	return ref, nil
}

func (r *vaultRegistry) list(ctx context.Context) ([]vaultReference, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT name, path, last_opened_at,
       preferred_device_path, preferred_device_product, preferred_device_manufacturer,
       preferred_device_vendor_id, preferred_device_product_id
FROM vault_registry
ORDER BY CASE WHEN last_opened_at = '' THEN 1 ELSE 0 END,
         last_opened_at DESC,
         name COLLATE BINARY`)
	if err != nil {
		return nil, fmt.Errorf("list vault references: %w", err)
	}
	defer rows.Close()

	refs := make([]vaultReference, 0)
	for rows.Next() {
		var ref vaultReference
		if err := rows.Scan(
			&ref.Name,
			&ref.Path,
			&ref.LastOpenedAt,
			&ref.PreferredDevicePath,
			&ref.PreferredDeviceProduct,
			&ref.PreferredDeviceManufacturer,
			&ref.PreferredDeviceVendorID,
			&ref.PreferredDeviceProductID,
		); err != nil {
			return nil, fmt.Errorf("scan vault reference: %w", err)
		}
		ref.Available = vaultDirectoryAvailable(ref.Path)
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list vault references: %w", err)
	}
	return refs, nil
}

func (r *vaultRegistry) touch(ctx context.Context, path string) error {
	result, err := r.db.ExecContext(ctx, `
UPDATE vault_registry
SET last_opened_at = ?
WHERE path = ?`, time.Now().UTC().Format(time.RFC3339Nano), path)
	if err != nil {
		return fmt.Errorf("update vault access time: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update vault access time: %w", err)
	}
	if affected == 0 {
		return errVaultReferenceNotFound
	}
	return nil
}

func (r *vaultRegistry) rememberDevice(ctx context.Context, path string, device authenticatorInfo) error {
	result, err := r.db.ExecContext(ctx, `
UPDATE vault_registry
SET preferred_device_path = ?,
    preferred_device_product = ?,
    preferred_device_manufacturer = ?,
    preferred_device_vendor_id = ?,
    preferred_device_product_id = ?
WHERE path = ?`,
		device.Path,
		device.Product,
		device.Manufacturer,
		device.VendorID,
		device.ProductID,
		path,
	)
	if err != nil {
		return fmt.Errorf("remember vault authenticator: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("remember vault authenticator: %w", err)
	}
	if affected == 0 {
		return errVaultReferenceNotFound
	}
	return nil
}

func (r *vaultRegistry) close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

func normalizeVaultPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("vault directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve vault directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	return absolute, nil
}

func validateVaultDirectory(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create vault directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect vault directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("vault path must be a directory")
	}
	keysExists := fileExists(filepath.Join(path, "keys.sqlite"))
	valuesExist := vaultValueFileSetExists(path)
	if keysExists != valuesExist {
		return errors.New("vault directory contains an incomplete vault")
	}
	return nil
}

func vaultValueFileSetExists(path string) bool {
	return fileExists(filepath.Join(path, vaultValueFilename)) ||
		fileExists(filepath.Join(path, vaultValueShadowFilename)) ||
		fileExists(filepath.Join(path, vaultValueBackupFilename))
}

func vaultDirectoryAvailable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
