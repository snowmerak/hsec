package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	"github.com/snowmerak/hmacsecret/lib/store"
	encryptedstore "github.com/snowmerak/hmacsecret/pkg/store/encrypted"
	sqlitestore "github.com/snowmerak/hmacsecret/pkg/store/sqlite"
)

const (
	vaultRPID     = "hsec.local"
	vaultRPName   = "hsec"
	vaultDEKAlias = "vault-dek"
)

type vaultStatus struct {
	Initialized bool   `json:"initialized"`
	Unlocked    bool   `json:"unlocked"`
	Selected    bool   `json:"selected"`
	VaultName   string `json:"vaultName"`
	VaultPath   string `json:"vaultPath"`
}

type authenticatorInfo struct {
	Index        int    `json:"index"`
	Path         string `json:"path"`
	Product      string `json:"product"`
	Manufacturer string `json:"manufacturer"`
	ProductID    int16  `json:"productId"`
	VendorID     int16  `json:"vendorId"`
	WindowsHello bool   `json:"windowsHello"`
}

type fidoEvent struct {
	OperationID string `json:"operationId"`
	Phase       string `json:"phase"`
	Message     string `json:"message"`
}

type fidoAuthenticator interface {
	CreateCredential(opts hmacsecret.CreateOptions) (*hmacsecret.Credential, error)
	Derive(opts hmacsecret.DeriveOptions) (*hmacsecret.Secret, error)
}

type VaultService struct {
	mu sync.Mutex

	registry *vaultRegistry
	selected vaultReference
	metadata *encryptedstore.Store
	values   *vaultValueStore
	vaultDEK *memguard.Enclave

	devices  func(hmacsecret.ListOptions) ([]hmacsecret.DeviceInfo, error)
	open     func(string) (fidoAuthenticator, error)
	emit     func(string, any)
	fidoWait time.Duration
}

func NewVaultService(appDataDir string) (*VaultService, error) {
	if appDataDir == "" {
		return nil, errors.New("application data directory is required")
	}
	if err := os.MkdirAll(appDataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create application data directory: %w", err)
	}
	registryPath := filepath.Join(appDataDir, "registry.sqlite")
	registry, err := openVaultRegistry(registryPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(registryPath, 0o600)

	// Register the pre-registry default vault in place. Nothing is moved.
	if fileExists(filepath.Join(appDataDir, "keys.sqlite")) &&
		fileExists(filepath.Join(appDataDir, "vault.sqlite")) {
		if _, err := registry.add(context.Background(), appDataDir); err != nil {
			_ = registry.close()
			return nil, fmt.Errorf("register existing default vault: %w", err)
		}
	}

	return &VaultService{
		registry: registry,
		devices:  hmacsecret.ListDevices,
		open: func(path string) (fidoAuthenticator, error) {
			return hmacsecret.Open(path)
		},
		emit:     func(string, any) {},
		fidoWait: time.Second,
	}, nil
}

func openVaultStores(dataDir string) (*encryptedstore.Store, *vaultValueStore, error) {
	if err := validateVaultDirectory(dataDir); err != nil {
		return nil, nil, err
	}
	backend, err := sqlitestore.Open(filepath.Join(dataDir, "keys.sqlite"))
	if err != nil {
		return nil, nil, err
	}
	metadata, err := encryptedstore.New(backend)
	if err != nil {
		_ = backend.Close()
		return nil, nil, err
	}
	values, err := openVaultValueStore(filepath.Join(dataDir, "vault.sqlite"))
	if err != nil {
		_ = metadata.Close()
		return nil, nil, err
	}
	for _, filename := range []string{"keys.sqlite", "vault.sqlite"} {
		_ = os.Chmod(filepath.Join(dataDir, filename), 0o600)
	}
	return metadata, values, nil
}

func defaultVaultDataDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(configDir, "hsec"), nil
}

func (s *VaultService) closeSelectedLocked() error {
	s.lockLocked()
	var valueErr, metadataErr error
	if s.values != nil {
		valueErr = s.values.close()
	}
	if s.metadata != nil {
		metadataErr = s.metadata.Close()
	}
	s.values = nil
	s.metadata = nil
	s.selected = vaultReference{}
	return errors.Join(valueErr, metadataErr)
}

func (s *VaultService) setEmitter(emit func(string, any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if emit == nil {
		s.emit = func(string, any) {}
		return
	}
	s.emit = emit
}

func (s *VaultService) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	vaultErr := s.closeSelectedLocked()
	registryErr := s.registry.close()
	return errors.Join(vaultErr, registryErr)
}

func (s *VaultService) Status(ctx context.Context) (vaultStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked(ctx)
}

func (s *VaultService) Vaults(ctx context.Context) ([]vaultReference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registry.list(ctx)
}

func (s *VaultService) AddVault(ctx context.Context, path string) (vaultReference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registry.add(ctx, path)
}

func (s *VaultService) SelectVault(ctx context.Context, path string) (vaultStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ref, err := s.registry.get(ctx, path)
	if err != nil {
		return vaultStatus{}, err
	}
	if !ref.Available {
		return vaultStatus{}, errors.New("vault directory is not available")
	}
	if s.metadata != nil && s.selected.Path == ref.Path {
		if err := s.registry.touch(ctx, ref.Path); err != nil {
			return vaultStatus{}, err
		}
		s.selected, _ = s.registry.get(ctx, ref.Path)
		return s.statusLocked(ctx)
	}
	if err := s.closeSelectedLocked(); err != nil {
		return vaultStatus{}, err
	}
	metadata, values, err := openVaultStores(ref.Path)
	if err != nil {
		return vaultStatus{}, err
	}
	s.metadata = metadata
	s.values = values
	s.selected = ref
	if err := s.registry.touch(ctx, ref.Path); err != nil {
		_ = s.closeSelectedLocked()
		return vaultStatus{}, err
	}
	s.selected, _ = s.registry.get(ctx, ref.Path)
	return s.statusLocked(ctx)
}

func (s *VaultService) CloseVault() (vaultStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.closeSelectedLocked(); err != nil {
		return vaultStatus{}, err
	}
	return vaultStatus{}, nil
}

func (s *VaultService) Authenticators() ([]authenticatorInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	devices, err := s.devices(hmacsecret.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("find FIDO2 security keys: %w", err)
	}
	out := make([]authenticatorInfo, 0, len(devices))
	for _, device := range devices {
		out = append(out, authenticatorInfoFromDevice(device))
	}
	return out, nil
}

func (s *VaultService) statusLocked(ctx context.Context) (vaultStatus, error) {
	if s.metadata == nil {
		return vaultStatus{}, nil
	}
	_, err := s.metadata.Header(ctx)
	if errors.Is(err, store.ErrNotInitialized) {
		return vaultStatus{
			Selected:  true,
			VaultName: s.selected.Name,
			VaultPath: s.selected.Path,
		}, nil
	}
	if err != nil {
		return vaultStatus{}, fmt.Errorf("read vault status: %w", err)
	}
	return vaultStatus{
		Initialized: true,
		Unlocked:    s.vaultDEK != nil,
		Selected:    true,
		VaultName:   s.selected.Name,
		VaultPath:   s.selected.Path,
	}, nil
}

func (s *VaultService) Initialize(ctx context.Context, devicePath, pin string) (vaultStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.metadata == nil {
		return vaultStatus{}, errors.New("select a vault before initializing")
	}
	if _, err := s.metadata.Header(ctx); err == nil {
		return vaultStatus{}, errors.New("vault is already initialized")
	} else if !errors.Is(err, store.ErrNotInitialized) {
		return vaultStatus{}, fmt.Errorf("check vault initialization: %w", err)
	}

	auth, device, err := s.openAuthenticator(devicePath)
	if err != nil {
		return vaultStatus{}, err
	}
	rootSalt := make([]byte, store.SaltSize)
	if _, err := rand.Read(rootSalt); err != nil {
		return vaultStatus{}, fmt.Errorf("generate root salt: %w", err)
	}
	rootCredential, err := s.createCredential(auth, pin, "root-kek")
	if err != nil {
		return vaultStatus{}, err
	}
	rootKEK, err := s.derive(auth, pin, store.KEKReference{
		CredentialID: rootCredential.ID,
		Salt:         rootSalt,
		RPID:         vaultRPID,
	}, "root-kek")
	if err != nil {
		return vaultStatus{}, err
	}

	dekRecord, dek, err := s.provisionVaultDEK(auth, pin)
	if err != nil {
		return vaultStatus{}, err
	}
	if err := s.metadata.Initialize(ctx, store.KEKReference{
		CredentialID: rootCredential.ID,
		Salt:         rootSalt,
		RPID:         vaultRPID,
	}, rootKEK); err != nil {
		return vaultStatus{}, fmt.Errorf("initialize encrypted key store: %w", err)
	}
	if err := s.metadata.Put(ctx, dekRecord); err != nil {
		s.metadata.Lock()
		return vaultStatus{}, fmt.Errorf("store encrypted vault DEK reference: %w", err)
	}
	s.vaultDEK = dek
	if err := s.registry.rememberDevice(ctx, s.selected.Path, device); err != nil {
		s.lockLocked()
		return vaultStatus{}, err
	}
	s.selected, _ = s.registry.get(ctx, s.selected.Path)
	return s.statusLocked(ctx)
}

func (s *VaultService) Unlock(ctx context.Context, devicePath, pin string) (vaultStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.metadata == nil {
		return vaultStatus{}, errors.New("select a vault before unlocking")
	}
	if s.vaultDEK != nil {
		return s.statusLocked(ctx)
	}
	header, err := s.metadata.Header(ctx)
	if errors.Is(err, store.ErrNotInitialized) {
		return vaultStatus{}, errors.New("vault is not initialized")
	}
	if err != nil {
		return vaultStatus{}, fmt.Errorf("load vault header: %w", err)
	}

	auth, device, err := s.openAuthenticator(devicePath)
	if err != nil {
		return vaultStatus{}, err
	}
	rootKEK, err := s.derive(auth, pin, header.KEK, "root-kek")
	if err != nil {
		return vaultStatus{}, err
	}
	if err := s.metadata.Unlock(ctx, rootKEK); err != nil {
		return vaultStatus{}, fmt.Errorf("unlock encrypted key store: %w", err)
	}

	record, err := s.metadata.Get(ctx, vaultDEKAlias)
	if err != nil {
		s.metadata.Lock()
		return vaultStatus{}, fmt.Errorf("load vault DEK reference: %w", err)
	}
	dek, err := s.derive(auth, pin, store.KEKReference{
		CredentialID: record.CredentialID,
		Salt:         record.Salt,
		RPID:         record.RPID,
	}, "vault-dek")
	if err != nil {
		s.metadata.Lock()
		return vaultStatus{}, err
	}
	s.vaultDEK = dek
	if err := s.registry.rememberDevice(ctx, s.selected.Path, device); err != nil {
		s.lockLocked()
		return vaultStatus{}, err
	}
	s.selected, _ = s.registry.get(ctx, s.selected.Path)
	return s.statusLocked(ctx)
}

// RotateKEK replaces the public root credential reference and rewraps the
// metadata-store DEK without rewriting the encrypted vault metadata or values.
// The vault must already be unlocked so the existing metadata-store DEK is
// available for rewrapping.
func (s *VaultService) RotateKEK(ctx context.Context, devicePath, pin string) (vaultStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.metadata == nil {
		return vaultStatus{}, errors.New("select a vault before rotating its KEK")
	}
	if s.vaultDEK == nil {
		return vaultStatus{}, errors.New("vault is locked")
	}

	auth, device, err := s.openAuthenticator(devicePath)
	if err != nil {
		return vaultStatus{}, err
	}
	dekRecord, err := s.metadata.Get(ctx, vaultDEKAlias)
	if err != nil {
		return vaultStatus{}, fmt.Errorf("load vault DEK reference before KEK rotation: %w", err)
	}
	if _, err := s.derive(auth, pin, store.KEKReference{
		CredentialID: dekRecord.CredentialID,
		Salt:         dekRecord.Salt,
		RPID:         dekRecord.RPID,
	}, "vault-dek-validation"); err != nil {
		return vaultStatus{}, fmt.Errorf("selected authenticator cannot derive the current vault DEK: %w", err)
	}
	salt := make([]byte, store.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return vaultStatus{}, fmt.Errorf("generate rotated root salt: %w", err)
	}
	credential, err := s.createCredential(auth, pin, "root-kek-rotation")
	if err != nil {
		return vaultStatus{}, err
	}
	nextRef := store.KEKReference{
		CredentialID: credential.ID,
		Salt:         salt,
		RPID:         vaultRPID,
	}
	nextKEK, err := s.derive(auth, pin, nextRef, "root-kek-rotation")
	if err != nil {
		return vaultStatus{}, err
	}

	previousDevice := authenticatorInfo{
		Path:         s.selected.PreferredDevicePath,
		Product:      s.selected.PreferredDeviceProduct,
		Manufacturer: s.selected.PreferredDeviceManufacturer,
		VendorID:     s.selected.PreferredDeviceVendorID,
		ProductID:    s.selected.PreferredDeviceProductID,
	}
	if err := s.registry.rememberDevice(ctx, s.selected.Path, device); err != nil {
		return vaultStatus{}, err
	}
	if err := s.metadata.RotateKEK(ctx, nextRef, nextKEK); err != nil {
		_ = s.registry.rememberDevice(context.Background(), s.selected.Path, previousDevice)
		return vaultStatus{}, fmt.Errorf("rotate vault KEK: %w", err)
	}

	s.selected.PreferredDevicePath = device.Path
	s.selected.PreferredDeviceProduct = device.Product
	s.selected.PreferredDeviceManufacturer = device.Manufacturer
	s.selected.PreferredDeviceVendorID = device.VendorID
	s.selected.PreferredDeviceProductID = device.ProductID
	return s.statusLocked(ctx)
}

func (s *VaultService) Lock() vaultStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockLocked()
	status, _ := s.statusLocked(context.Background())
	return status
}

func (s *VaultService) List(ctx context.Context) ([]vaultEntrySummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vaultDEK == nil {
		return nil, errors.New("vault is locked")
	}
	return s.values.list(ctx)
}

func (s *VaultService) Get(ctx context.Context, alias string) (vaultEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vaultDEK == nil || s.values == nil {
		return vaultEntry{}, errors.New("vault is locked")
	}
	return s.values.get(ctx, alias, s.vaultDEK)
}

func (s *VaultService) Create(ctx context.Context, alias string, value vaultValueDocument) (vaultEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vaultDEK == nil || s.values == nil {
		return vaultEntry{}, errors.New("vault is locked")
	}
	return s.values.create(ctx, alias, value, s.vaultDEK)
}

func (s *VaultService) Update(ctx context.Context, alias string, value vaultValueDocument, expectedRevision uint64) (vaultEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vaultDEK == nil || s.values == nil {
		return vaultEntry{}, errors.New("vault is locked")
	}
	return s.values.update(ctx, alias, value, expectedRevision, s.vaultDEK)
}

func (s *VaultService) Delete(ctx context.Context, alias string, expectedRevision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vaultDEK == nil || s.values == nil {
		return errors.New("vault is locked")
	}
	return s.values.delete(ctx, alias, expectedRevision)
}

func (s *VaultService) provisionVaultDEK(auth fidoAuthenticator, pin string) (store.Record, *memguard.Enclave, error) {
	salt := make([]byte, store.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return store.Record{}, nil, fmt.Errorf("generate vault DEK salt: %w", err)
	}
	credential, err := s.createCredential(auth, pin, "vault-dek")
	if err != nil {
		return store.Record{}, nil, err
	}
	record := store.Record{
		Alias:        vaultDEKAlias,
		CredentialID: credential.ID,
		Salt:         salt,
		RPID:         vaultRPID,
	}
	dek, err := s.derive(auth, pin, store.KEKReference{
		CredentialID: record.CredentialID,
		Salt:         record.Salt,
		RPID:         record.RPID,
	}, "vault-dek")
	if err != nil {
		return store.Record{}, nil, err
	}
	return record, dek, nil
}

func (s *VaultService) openAuthenticator(path string) (fidoAuthenticator, authenticatorInfo, error) {
	devices, err := s.devices(hmacsecret.ListOptions{})
	if err != nil {
		return nil, authenticatorInfo{}, fmt.Errorf("find FIDO2 security key: %w", err)
	}
	if len(devices) == 0 {
		return nil, authenticatorInfo{}, errors.New("no FIDO2 security key found")
	}
	if path == "" {
		if len(devices) != 1 {
			return nil, authenticatorInfo{}, errors.New("select a FIDO2 security key")
		}
		path = devices[0].Path
	}
	var selected *hmacsecret.DeviceInfo
	for index := range devices {
		if devices[index].Path == path {
			selected = &devices[index]
			break
		}
	}
	if selected == nil {
		return nil, authenticatorInfo{}, errors.New("selected FIDO2 security key is not connected")
	}
	auth, err := s.open(selected.Path)
	if err != nil {
		return nil, authenticatorInfo{}, fmt.Errorf("open FIDO2 security key: %w", err)
	}
	return auth, authenticatorInfoFromDevice(*selected), nil
}

func authenticatorInfoFromDevice(device hmacsecret.DeviceInfo) authenticatorInfo {
	return authenticatorInfo{
		Index:        device.Index,
		Path:         device.Path,
		Product:      device.Product,
		Manufacturer: device.Manufacturer,
		ProductID:    device.ProductID,
		VendorID:     device.VendorID,
		WindowsHello: device.WindowsHello,
	}
}

func (s *VaultService) createCredential(auth fidoAuthenticator, pin, phase string) (*hmacsecret.Credential, error) {
	var credential *hmacsecret.Credential
	err := s.withFIDOToast(phase, func() error {
		var err error
		credential, err = auth.CreateCredential(hmacsecret.CreateOptions{
			RPID:            vaultRPID,
			RPName:          vaultRPName,
			UserName:        "hsec",
			UserDisplayName: "hsec vault",
			PIN:             pin,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create %s credential: %w", phase, err)
	}
	return credential, nil
}

func (s *VaultService) derive(auth fidoAuthenticator, pin string, ref store.KEKReference, phase string) (*memguard.Enclave, error) {
	var secret *hmacsecret.Secret
	err := s.withFIDOToast(phase, func() error {
		var err error
		secret, err = auth.Derive(hmacsecret.DeriveOptions{
			RPID:         ref.RPID,
			CredentialID: ref.CredentialID,
			Salt:         ref.Salt,
			PIN:          pin,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("derive %s: %w", phase, err)
	}
	if secret == nil || secret.HMACSecret == nil {
		return nil, fmt.Errorf("derive %s: authenticator returned no secret", phase)
	}
	return secret.HMACSecret, nil
}

func (s *VaultService) withFIDOToast(phase string, operation func() error) error {
	operationID := randomOperationID()
	finished := make(chan struct{})
	notifierDone := make(chan struct{})
	go func() {
		defer close(notifierDone)
		timer := time.NewTimer(s.fidoWait)
		defer timer.Stop()
		select {
		case <-finished:
			return
		case <-timer.C:
			s.emit("vault:fido-waiting", fidoEvent{
				OperationID: operationID,
				Phase:       phase,
				Message:     "계속하려면 FIDO2 보안 키의 버튼을 누르세요.",
			})
			<-finished
			s.emit("vault:fido-resolved", fidoEvent{OperationID: operationID, Phase: phase})
		}
	}()

	err := operation()
	close(finished)
	<-notifierDone
	return err
}

func (s *VaultService) lockLocked() {
	if s.metadata != nil {
		s.metadata.Lock()
	}
	s.vaultDEK = nil
	memguard.Purge()
}

func randomOperationID() string {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(id[:])
}
