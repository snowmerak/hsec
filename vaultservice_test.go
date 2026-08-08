package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	"github.com/snowmerak/hmacsecret/lib/store"
)

type fakeAuthenticator struct {
	mu          sync.Mutex
	credentials int
	derivations int
	delay       time.Duration
	marker      byte
}

func (a *fakeAuthenticator) CreateCredential(opts hmacsecret.CreateOptions) (*hmacsecret.Credential, error) {
	time.Sleep(a.delay)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.credentials++
	return &hmacsecret.Credential{
		ID:   []byte{a.marker, byte(a.credentials), 0x48, 0x53, 0x45, 0x43},
		RPID: opts.RPID,
	}, nil
}

func (a *fakeAuthenticator) Derive(opts hmacsecret.DeriveOptions) (*hmacsecret.Secret, error) {
	time.Sleep(a.delay)
	a.mu.Lock()
	a.derivations++
	a.mu.Unlock()
	if len(opts.CredentialID) == 0 || opts.CredentialID[0] != a.marker {
		return nil, errors.New("credential is not available on this authenticator")
	}
	material := make([]byte, 0, len(opts.RPID)+len(opts.CredentialID)+len(opts.Salt))
	material = append(material, opts.RPID...)
	material = append(material, opts.CredentialID...)
	material = append(material, opts.Salt...)
	key := sha256.Sum256(material)
	return &hmacsecret.Secret{
		CredentialID: append([]byte(nil), opts.CredentialID...),
		Salt:         append([]byte(nil), opts.Salt...),
		HMACSecret:   memguard.NewEnclave(key[:]),
	}, nil
}

func (a *fakeAuthenticator) counts() (credentials, derivations int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.credentials, a.derivations
}

func TestRotateKEKRewrapsMetadataAndPersistsNewAuthenticator(t *testing.T) {
	ctx := context.Background()
	firstAuth := &fakeAuthenticator{marker: 1}
	secondAuth := &fakeAuthenticator{marker: 2}
	service, _ := newTestVaultService(t, firstAuth)
	devices := []hmacsecret.DeviceInfo{
		{Index: 0, Path: "fake://first", Product: "First Key", Manufacturer: "Example", VendorID: 1, ProductID: 2},
		{Index: 1, Path: "fake://second", Product: "Second Key", Manufacturer: "Example", VendorID: 3, ProductID: 4},
	}
	service.devices = func(hmacsecret.ListOptions) ([]hmacsecret.DeviceInfo, error) {
		return devices, nil
	}
	service.open = func(path string) (fidoAuthenticator, error) {
		switch path {
		case devices[0].Path:
			return firstAuth, nil
		case devices[1].Path:
			return secondAuth, nil
		default:
			return nil, errors.New("unknown authenticator")
		}
	}

	if _, err := service.Initialize(ctx, devices[0].Path, ""); err != nil {
		t.Fatal(err)
	}
	if credentials, derivations := firstAuth.counts(); credentials != 1 || derivations != 1 {
		t.Fatalf("initialization FIDO calls = (%d create, %d derive), want (1, 1)", credentials, derivations)
	}
	value := vaultValueDocument{
		Version: vaultValueDocumentVersion,
		Fields:  []vaultValueField{{Name: "token", Value: "survives-kek-rotation"}},
	}
	if _, err := service.Create(ctx, "rotation-test", value); err != nil {
		t.Fatal(err)
	}
	beforeHeader, err := service.metadata.Header(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.metadata.Get(ctx, vaultDEKAlias); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new vault stored a legacy FIDO vault-DEK credential: %v", err)
	}

	status, err := service.RotateKEK(ctx, devices[1].Path, "")
	if err != nil {
		t.Fatal(err)
	}
	if credentials, derivations := secondAuth.counts(); credentials != 1 || derivations != 1 {
		t.Fatalf("KEK rotation FIDO calls = (%d create, %d derive), want (1, 1)", credentials, derivations)
	}
	if !status.Initialized || !status.Unlocked {
		t.Fatalf("unexpected rotated status: %+v", status)
	}
	afterHeader, err := service.metadata.Header(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterHeader.Revision != beforeHeader.Revision+1 {
		t.Fatalf("header revision = %d, want %d", afterHeader.Revision, beforeHeader.Revision+1)
	}
	if bytes.Equal(afterHeader.KEK.CredentialID, beforeHeader.KEK.CredentialID) ||
		bytes.Equal(afterHeader.KEK.Salt, beforeHeader.KEK.Salt) {
		t.Fatal("rotated header retained the previous KEK reference")
	}
	if bytes.Equal(afterHeader.WrappedDEK.Ciphertext, beforeHeader.WrappedDEK.Ciphertext) {
		t.Fatal("metadata DEK was not rewrapped during KEK rotation")
	}
	var envelopeCount int
	var envelopeRevision uint64
	if err := service.vaultKeys.db.QueryRowContext(ctx, `
SELECT COUNT(*), MIN(header_revision) FROM vault_key_envelopes`).Scan(
		&envelopeCount, &envelopeRevision,
	); err != nil {
		t.Fatal(err)
	}
	if envelopeCount != 1 || envelopeRevision != afterHeader.Revision {
		t.Fatalf("wrapped vault DEKs = (%d at revision %d), want (1 at revision %d)", envelopeCount, envelopeRevision, afterHeader.Revision)
	}
	entry, err := service.Get(ctx, "rotation-test")
	if err != nil || entry.Value.Fields[0].Value != "survives-kek-rotation" {
		t.Fatalf("read after rotation: entry=%+v err=%v", entry, err)
	}
	refs, err := service.Vaults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].PreferredDevicePath != devices[1].Path {
		t.Fatalf("preferred authenticator was not rotated: %+v", refs)
	}

	service.Lock()
	if _, err := service.RotateKEK(ctx, devices[1].Path, ""); err == nil {
		t.Fatal("RotateKEK succeeded while vault was locked")
	}
	if _, err := service.Unlock(ctx, devices[0].Path, ""); err == nil {
		t.Fatal("previous authenticator unlocked the vault after KEK rotation")
	}
	if _, err := service.Unlock(ctx, devices[1].Path, ""); err != nil {
		t.Fatalf("authenticator did not unlock the vault with its rotated credential: %v", err)
	}
	if credentials, derivations := secondAuth.counts(); credentials != 1 || derivations != 2 {
		t.Fatalf("rotated authenticator calls after unlock = (%d create, %d derive), want (1, 2)", credentials, derivations)
	}
	entry, err = service.Get(ctx, "rotation-test")
	if err != nil || entry.Value.Fields[0].Value != "survives-kek-rotation" {
		t.Fatalf("read after unlocking rotated vault: entry=%+v err=%v", entry, err)
	}
}

func newTestVaultService(t *testing.T, auth *fakeAuthenticator) (*VaultService, string) {
	t.Helper()
	appDataDir := t.TempDir()
	vaultDir := filepath.Join(t.TempDir(), "test-vault")
	service, err := NewVaultService(appDataDir)
	if err != nil {
		t.Fatal(err)
	}
	service.devices = func(hmacsecret.ListOptions) ([]hmacsecret.DeviceInfo, error) {
		return []hmacsecret.DeviceInfo{{Path: "fake://security-key", Product: "Test Key"}}, nil
	}
	service.open = func(string) (fidoAuthenticator, error) {
		return auth, nil
	}
	ctx := context.Background()
	if _, err := service.AddVault(ctx, vaultDir); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SelectVault(ctx, vaultDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.close(); err != nil {
			t.Errorf("close service: %v", err)
		}
	})
	return service, vaultDir
}

func TestVaultLifecycleAndEncryptedStorage(t *testing.T) {
	auth := &fakeAuthenticator{}
	service, dataDir := newTestVaultService(t, auth)
	ctx := context.Background()

	status, err := service.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Initialized || status.Unlocked {
		t.Fatalf("unexpected initial status: %+v", status)
	}

	status, err = service.Initialize(ctx, "fake://security-key", "")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Initialized || !status.Unlocked {
		t.Fatalf("unexpected initialized status: %+v", status)
	}
	if credentials, derivations := auth.counts(); credentials != 1 || derivations != 1 {
		t.Fatalf("initialization FIDO calls = (%d create, %d derive), want (1, 1)", credentials, derivations)
	}

	const (
		alias  = "GitHub 개인 계정"
		secret = "do-not-store-this-plaintext"
	)
	value := vaultValueDocument{
		Version: vaultValueDocumentVersion,
		Fields: []vaultValueField{
			{Name: "사용자 이름", Value: "snowmerak"},
			{Name: "비밀번호", Value: secret},
		},
	}
	created, err := service.Create(ctx, alias, value)
	if err != nil {
		t.Fatal(err)
	}
	if created.Alias != alias || created.Revision != 1 {
		t.Fatalf("unexpected created entry: %+v", created)
	}

	loaded, err := service.Get(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Value.Fields) != 2 || loaded.Value.Fields[1].Value != secret {
		t.Fatalf("unexpected loaded value: %+v", loaded.Value)
	}

	nextValue := vaultValueDocument{
		Version: vaultValueDocumentVersion,
		Fields: []vaultValueField{
			{Name: "사용자 이름", Value: "snowmerak"},
			{Name: "비밀번호", Value: "rotated-secret"},
			{Name: "API 토큰", Value: "token-secret"},
		},
	}
	updated, err := service.Update(ctx, alias, nextValue, loaded.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 {
		t.Fatalf("got revision %d, want 2", updated.Revision)
	}
	if _, err := service.Update(ctx, alias, nextValue, loaded.Revision); err != errEntryConflict {
		t.Fatalf("got stale update error %v, want %v", err, errEntryConflict)
	}

	for _, filename := range []string{"keys.sqlite", "vault.sqlite"} {
		content, err := os.ReadFile(filepath.Join(dataDir, filename))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(content, []byte(secret)) ||
			bytes.Contains(content, []byte("rotated-secret")) ||
			bytes.Contains(content, []byte("API 토큰")) {
			t.Fatalf("%s contains plaintext secret", filename)
		}
	}

	service.Lock()
	if _, err := service.Get(ctx, alias); err == nil {
		t.Fatal("Get succeeded while vault was locked")
	}
	if _, err := service.Unlock(ctx, "fake://security-key", ""); err != nil {
		t.Fatal(err)
	}
	if credentials, derivations := auth.counts(); credentials != 1 || derivations != 2 {
		t.Fatalf("calls after unlock = (%d create, %d derive), want (1, 2)", credentials, derivations)
	}
	reloaded, err := service.Get(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Value.Fields) != 3 || reloaded.Value.Fields[1].Value != "rotated-secret" {
		t.Fatalf("unexpected value after unlock: %+v", reloaded.Value)
	}

	if err := service.Delete(ctx, alias, reloaded.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(ctx, alias); err != errEntryNotFound {
		t.Fatalf("got deleted entry error %v, want %v", err, errEntryNotFound)
	}
}

func TestRotateDEKReencryptsValuesWithoutFIDO(t *testing.T) {
	ctx := context.Background()
	auth := &fakeAuthenticator{}
	service, dataDir := newTestVaultService(t, auth)
	if _, err := service.Initialize(ctx, "fake://security-key", ""); err != nil {
		t.Fatal(err)
	}

	for i := range 12 {
		alias := fmt.Sprintf("entry-%02d", i)
		if _, err := service.Create(ctx, alias, vaultValueDocument{
			Version: vaultValueDocumentVersion,
			Fields:  []vaultValueField{{Name: "secret", Value: fmt.Sprintf("value-%02d", i)}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	var beforeCiphertext []byte
	if err := service.values.db.QueryRowContext(ctx,
		`SELECT ciphertext FROM vault_entries WHERE alias = ?`, "entry-00",
	).Scan(&beforeCiphertext); err != nil {
		t.Fatal(err)
	}
	credentialsBefore, derivationsBefore := auth.counts()

	var progress []dekRotationProgress
	service.setEmitter(func(name string, data any) {
		if name == "vault:dek-rotation-progress" {
			progress = append(progress, data.(dekRotationProgress))
		}
	})
	status, err := service.RotateDEK(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Unlocked {
		t.Fatalf("unexpected status after DEK rotation: %+v", status)
	}
	credentialsAfter, derivationsAfter := auth.counts()
	if credentialsAfter != credentialsBefore || derivationsAfter != derivationsBefore {
		t.Fatalf("DEK rotation used FIDO: before=(%d,%d) after=(%d,%d)", credentialsBefore, derivationsBefore, credentialsAfter, derivationsAfter)
	}
	if len(progress) < 4 || progress[0].Phase != "copying" || progress[len(progress)-1].Phase != "completed" {
		t.Fatalf("unexpected DEK rotation progress: %+v", progress)
	}
	last := progress[len(progress)-1]
	if last.Completed != 12 || last.Total != 12 || last.Percent != 100 {
		t.Fatalf("unexpected final DEK rotation progress: %+v", last)
	}

	var afterCiphertext []byte
	if err := service.values.db.QueryRowContext(ctx,
		`SELECT ciphertext FROM vault_entries WHERE alias = ?`, "entry-00",
	).Scan(&afterCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(beforeCiphertext, afterCiphertext) {
		t.Fatal("vault entry ciphertext did not change during DEK rotation")
	}
	for i := range 12 {
		alias := fmt.Sprintf("entry-%02d", i)
		entry, err := service.Get(ctx, alias)
		if err != nil || entry.Value.Fields[0].Value != fmt.Sprintf("value-%02d", i) {
			t.Fatalf("read %s after DEK rotation: entry=%+v err=%v", alias, entry, err)
		}
	}
	for _, filename := range []string{vaultValueShadowFilename, vaultValueBackupFilename} {
		if fileExists(filepath.Join(dataDir, filename)) {
			t.Fatalf("temporary DEK rotation file remains: %s", filename)
		}
	}
	staged, err := service.vaultKeys.hasStagedDEKRotation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if staged {
		t.Fatal("DEK rotation journal was not cleared")
	}

	service.Lock()
	if _, err := service.Unlock(ctx, "fake://security-key", ""); err != nil {
		t.Fatalf("unlock after DEK rotation: %v", err)
	}
	if _, err := service.Get(ctx, "entry-00"); err != nil {
		t.Fatalf("read after reopening rotated DEK: %v", err)
	}
}

func TestInterruptedDEKSwapIsCompletedOnReopen(t *testing.T) {
	ctx := context.Background()
	auth := &fakeAuthenticator{}
	service, dataDir := newTestVaultService(t, auth)
	if _, err := service.Initialize(ctx, "fake://security-key", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(ctx, "survivor", vaultValueDocument{
		Version: vaultValueDocumentVersion,
		Fields:  []vaultValueField{{Name: "secret", Value: "still-readable"}},
	}); err != nil {
		t.Fatal(err)
	}
	header, err := service.metadata.Header(ctx)
	if err != nil {
		t.Fatal(err)
	}
	newDEK, err := randomVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	shadowPath := filepath.Join(dataDir, vaultValueShadowFilename)
	shadow, err := openVaultValueStore(shadowPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyVaultValues(ctx, service.values, shadow, service.vaultDEK, newDEK, nil); err != nil {
		t.Fatal(err)
	}
	if err := shadow.close(); err != nil {
		t.Fatal(err)
	}
	if err := service.vaultKeys.stageDEKRotation(ctx, header.Revision, header.KEK, newDEK, service.rootKEK); err != nil {
		t.Fatal(err)
	}
	if err := service.values.close(); err != nil {
		t.Fatal(err)
	}
	service.values = nil
	if err := swapVaultValueFiles(dataDir); err != nil {
		t.Fatal(err)
	}

	// This is the crash point: both file renames completed, but the staged
	// wrapper has not yet replaced the old vault-DEK envelope.
	if err := recoverDEKRotationFiles(dataDir, service.vaultKeys); err != nil {
		t.Fatal(err)
	}
	service.values, err = openVaultValueStore(filepath.Join(dataDir, vaultValueFilename))
	if err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(dataDir, vaultValueBackupFilename)) {
		t.Fatal("old vault database remains after recovery")
	}
	staged, err := service.vaultKeys.hasStagedDEKRotation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if staged {
		t.Fatal("recovered DEK rotation journal was not cleared")
	}

	service.Lock()
	if _, err := service.Unlock(ctx, "fake://security-key", ""); err != nil {
		t.Fatalf("unlock recovered vault: %v", err)
	}
	entry, err := service.Get(ctx, "survivor")
	if err != nil || entry.Value.Fields[0].Value != "still-readable" {
		t.Fatalf("read recovered entry: entry=%+v err=%v", entry, err)
	}
}

func TestInterruptedDEKPreparationKeepsOriginalDatabase(t *testing.T) {
	ctx := context.Background()
	auth := &fakeAuthenticator{}
	service, dataDir := newTestVaultService(t, auth)
	if _, err := service.Initialize(ctx, "fake://security-key", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(ctx, "original", vaultValueDocument{
		Version: vaultValueDocumentVersion,
		Fields:  []vaultValueField{{Name: "secret", Value: "old-db-remains-authoritative"}},
	}); err != nil {
		t.Fatal(err)
	}
	header, err := service.metadata.Header(ctx)
	if err != nil {
		t.Fatal(err)
	}
	newDEK, err := randomVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	shadowPath := filepath.Join(dataDir, vaultValueShadowFilename)
	shadow, err := openVaultValueStore(shadowPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyVaultValues(ctx, service.values, shadow, service.vaultDEK, newDEK, nil); err != nil {
		t.Fatal(err)
	}
	if err := shadow.close(); err != nil {
		t.Fatal(err)
	}
	if err := service.vaultKeys.stageDEKRotation(ctx, header.Revision, header.KEK, newDEK, service.rootKEK); err != nil {
		t.Fatal(err)
	}

	// This is the crash point before either live-file rename. Recovery must
	// discard the shadow and leave both the live DB and old wrapper untouched.
	if err := recoverDEKRotationFiles(dataDir, service.vaultKeys); err != nil {
		t.Fatal(err)
	}
	if fileExists(shadowPath) {
		t.Fatal("pre-swap shadow database remains after recovery")
	}
	staged, err := service.vaultKeys.hasStagedDEKRotation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if staged {
		t.Fatal("pre-swap DEK rotation journal remains after recovery")
	}
	service.Lock()
	if _, err := service.Unlock(ctx, "fake://security-key", ""); err != nil {
		t.Fatal(err)
	}
	entry, err := service.Get(ctx, "original")
	if err != nil || entry.Value.Fields[0].Value != "old-db-remains-authoritative" {
		t.Fatalf("read original entry after recovery: entry=%+v err=%v", entry, err)
	}
}

func TestLegacyVaultDEKIsMigratedAfterFirstUnlock(t *testing.T) {
	ctx := context.Background()
	auth := &fakeAuthenticator{marker: 7}
	service, _ := newTestVaultService(t, auth)

	rootSalt := make([]byte, store.SaltSize)
	if _, err := rand.Read(rootSalt); err != nil {
		t.Fatal(err)
	}
	rootCredential, err := service.createCredential(auth, "", "root-kek")
	if err != nil {
		t.Fatal(err)
	}
	rootRef := store.KEKReference{
		CredentialID: rootCredential.ID,
		Salt:         rootSalt,
		RPID:         vaultRPID,
	}
	rootKEK, err := service.derive(auth, "", rootRef, "root-kek")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.metadata.Initialize(ctx, rootRef, rootKEK); err != nil {
		t.Fatal(err)
	}

	legacySalt := make([]byte, store.SaltSize)
	if _, err := rand.Read(legacySalt); err != nil {
		t.Fatal(err)
	}
	legacyCredential, err := service.createCredential(auth, "", vaultDEKAlias)
	if err != nil {
		t.Fatal(err)
	}
	legacyRef := store.KEKReference{
		CredentialID: legacyCredential.ID,
		Salt:         legacySalt,
		RPID:         vaultRPID,
	}
	legacyDEK, err := service.derive(auth, "", legacyRef, vaultDEKAlias)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.metadata.Put(ctx, store.Record{
		Alias:        vaultDEKAlias,
		CredentialID: legacyRef.CredentialID,
		Salt:         legacyRef.Salt,
		RPID:         legacyRef.RPID,
	}); err != nil {
		t.Fatal(err)
	}
	service.vaultDEK = legacyDEK
	if _, err := service.Create(ctx, "legacy-entry", vaultValueDocument{
		Version: vaultValueDocumentVersion,
		Fields:  []vaultValueField{{Name: "token", Value: "migrated-secret"}},
	}); err != nil {
		t.Fatal(err)
	}
	service.Lock()

	if credentials, derivations := auth.counts(); credentials != 2 || derivations != 2 {
		t.Fatalf("legacy setup FIDO calls = (%d create, %d derive), want (2, 2)", credentials, derivations)
	}
	if _, err := service.Unlock(ctx, "fake://security-key", ""); err != nil {
		t.Fatal(err)
	}
	if credentials, derivations := auth.counts(); credentials != 2 || derivations != 4 {
		t.Fatalf("migration unlock calls = (%d create, %d derive), want (2, 4)", credentials, derivations)
	}
	if _, err := service.metadata.Get(ctx, vaultDEKAlias); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy vault-DEK reference was not removed: %v", err)
	}
	var envelopeCount int
	if err := service.vaultKeys.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vault_key_envelopes`,
	).Scan(&envelopeCount); err != nil {
		t.Fatal(err)
	}
	if envelopeCount != 1 {
		t.Fatalf("wrapped vault DEK count = %d, want 1", envelopeCount)
	}
	entry, err := service.Get(ctx, "legacy-entry")
	if err != nil || entry.Value.Fields[0].Value != "migrated-secret" {
		t.Fatalf("read migrated entry: entry=%+v err=%v", entry, err)
	}

	service.Lock()
	if _, err := service.Unlock(ctx, "fake://security-key", ""); err != nil {
		t.Fatal(err)
	}
	if credentials, derivations := auth.counts(); credentials != 2 || derivations != 5 {
		t.Fatalf("post-migration unlock calls = (%d create, %d derive), want (2, 5)", credentials, derivations)
	}
}

func TestLegacyStringValueIsPromotedToMemoField(t *testing.T) {
	service, _ := newTestVaultService(t, &fakeAuthenticator{})
	ctx := context.Background()
	if _, err := service.Initialize(ctx, "fake://security-key", ""); err != nil {
		t.Fatal(err)
	}

	const (
		alias  = "legacy"
		legacy = "legacy plaintext value"
	)
	nonce, ciphertext, err := sealVaultValue(service.vaultDEK, alias, 1, []byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := service.values.db.ExecContext(ctx, `
INSERT INTO vault_entries (alias, revision, nonce, ciphertext, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`, alias, 1, nonce, ciphertext, now, now); err != nil {
		t.Fatal(err)
	}

	entry, err := service.Get(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Value.Version != vaultValueDocumentVersion ||
		len(entry.Value.Fields) != 1 ||
		entry.Value.Fields[0].Name != "메모" ||
		entry.Value.Fields[0].Value != legacy {
		t.Fatalf("unexpected promoted value: %+v", entry.Value)
	}
}

func TestFIDOToastOnlyAfterWaitAndResolves(t *testing.T) {
	service, _ := newTestVaultService(t, &fakeAuthenticator{})
	service.fidoWait = 5 * time.Millisecond

	var mu sync.Mutex
	var names []string
	service.setEmitter(func(name string, _ any) {
		mu.Lock()
		names = append(names, name)
		mu.Unlock()
	})

	if err := service.withFIDOToast("test", func() error {
		time.Sleep(12 * time.Millisecond)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"vault:fido-waiting", "vault:fido-resolved"}
	if len(names) != len(want) {
		t.Fatalf("events = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("events = %v, want %v", names, want)
		}
	}
}

func TestFIDOToastDoesNotAppearForFastOperation(t *testing.T) {
	service, _ := newTestVaultService(t, &fakeAuthenticator{})
	service.fidoWait = 20 * time.Millisecond
	var emitted bool
	service.setEmitter(func(string, any) { emitted = true })

	if err := service.withFIDOToast("test", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if emitted {
		t.Fatal("toast event emitted for a fast operation")
	}
}

func TestVaultRegistryPersistsFolderAndSelectedAuthenticator(t *testing.T) {
	ctx := context.Background()
	appDataDir := t.TempDir()
	vaultDir := filepath.Join(t.TempDir(), "Google Drive", "personal")
	auth := &fakeAuthenticator{}

	service, err := NewVaultService(appDataDir)
	if err != nil {
		t.Fatal(err)
	}
	devices := []hmacsecret.DeviceInfo{
		{Index: 0, Path: "fake://first", Product: "First Key", Manufacturer: "Example", VendorID: 1, ProductID: 2},
		{Index: 1, Path: "fake://second", Product: "Second Key", Manufacturer: "Example", VendorID: 3, ProductID: 4},
	}
	service.devices = func(hmacsecret.ListOptions) ([]hmacsecret.DeviceInfo, error) {
		return devices, nil
	}
	var openedPath string
	service.open = func(path string) (fidoAuthenticator, error) {
		openedPath = path
		return auth, nil
	}

	ref, err := service.AddVault(ctx, vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.SelectVault(ctx, ref.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Selected || status.Initialized || status.VaultPath != ref.Path {
		t.Fatalf("unexpected selected status: %+v", status)
	}
	if _, err := service.Initialize(ctx, "", ""); err == nil {
		t.Fatal("Initialize succeeded without selecting one of multiple authenticators")
	}
	if _, err := service.Initialize(ctx, devices[1].Path, ""); err != nil {
		t.Fatal(err)
	}
	if openedPath != devices[1].Path {
		t.Fatalf("opened %q, want %q", openedPath, devices[1].Path)
	}
	if err := service.close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewVaultService(appDataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.close(); err != nil {
			t.Errorf("close reopened service: %v", err)
		}
	})
	refs, err := reopened.Vaults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 ||
		refs[0].Path != ref.Path ||
		refs[0].PreferredDevicePath != devices[1].Path ||
		refs[0].PreferredDeviceVendorID != devices[1].VendorID ||
		refs[0].PreferredDeviceProductID != devices[1].ProductID {
		t.Fatalf("unexpected persisted reference: %+v", refs)
	}
	for _, filename := range []string{"keys.sqlite", "vault.sqlite"} {
		if !fileExists(filepath.Join(ref.Path, filename)) {
			t.Fatalf("%s was not created in selected vault directory", filename)
		}
		if fileExists(filepath.Join(appDataDir, filename)) {
			t.Fatalf("%s was unexpectedly created in application registry directory", filename)
		}
	}
	if !fileExists(filepath.Join(appDataDir, "registry.sqlite")) {
		t.Fatal("registry.sqlite was not created in application data directory")
	}
}

func TestExistingDefaultVaultIsRegisteredInPlace(t *testing.T) {
	appDataDir := t.TempDir()
	metadata, vaultKeys, values, err := openVaultStores(appDataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(values.close(), vaultKeys.close(), metadata.Close()); err != nil {
		t.Fatal(err)
	}

	service, err := NewVaultService(appDataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.close(); err != nil {
			t.Errorf("close service: %v", err)
		}
	})
	refs, err := service.Vaults(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeVaultPath(appDataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Path != normalized {
		t.Fatalf("existing default vault was not registered in place: %+v", refs)
	}
}
