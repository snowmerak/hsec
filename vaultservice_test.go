package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
)

type fakeAuthenticator struct {
	mu          sync.Mutex
	credentials int
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
	beforeDEKRef, err := service.metadata.Get(ctx, vaultDEKAlias)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.RotateKEK(ctx, devices[1].Path, ""); err == nil {
		t.Fatal("RotateKEK accepted an authenticator without the current vault DEK credential")
	}
	rejectedHeader, err := service.metadata.Header(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rejectedHeader.Revision != beforeHeader.Revision ||
		!bytes.Equal(rejectedHeader.KEK.CredentialID, beforeHeader.KEK.CredentialID) {
		t.Fatal("rejected rotation changed the KEK header")
	}

	status, err := service.RotateKEK(ctx, devices[0].Path, "")
	if err != nil {
		t.Fatal(err)
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
	afterDEKRef, err := service.metadata.Get(ctx, vaultDEKAlias)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterDEKRef.CredentialID, beforeDEKRef.CredentialID) ||
		!bytes.Equal(afterDEKRef.Salt, beforeDEKRef.Salt) {
		t.Fatal("vault DEK reference changed during KEK rotation")
	}
	entry, err := service.Get(ctx, "rotation-test")
	if err != nil || entry.Value.Fields[0].Value != "survives-kek-rotation" {
		t.Fatalf("read after rotation: entry=%+v err=%v", entry, err)
	}
	refs, err := service.Vaults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].PreferredDevicePath != devices[0].Path {
		t.Fatalf("preferred authenticator was not rotated: %+v", refs)
	}

	service.Lock()
	if _, err := service.RotateKEK(ctx, devices[0].Path, ""); err == nil {
		t.Fatal("RotateKEK succeeded while vault was locked")
	}
	if _, err := service.Unlock(ctx, devices[0].Path, ""); err != nil {
		t.Fatalf("authenticator did not unlock the vault with its rotated credential: %v", err)
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
	service, dataDir := newTestVaultService(t, &fakeAuthenticator{})
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
	metadata, values, err := openVaultStores(appDataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(values.close(), metadata.Close()); err != nil {
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
