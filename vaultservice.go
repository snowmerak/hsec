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

	registry  *vaultRegistry
	selected  vaultReference
	metadata  *encryptedstore.Store
	vaultKeys *vaultKeyEnvelopeStore
	values    *vaultValueStore
	rootKEK   *memguard.Enclave
	vaultDEK  *memguard.Enclave

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
		vaultValueFileSetExists(appDataDir) {
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

func openVaultStores(dataDir string) (*encryptedstore.Store, *vaultKeyEnvelopeStore, *vaultValueStore, error) {
	if err := validateVaultDirectory(dataDir); err != nil {
		return nil, nil, nil, err
	}
	keysPath := filepath.Join(dataDir, "keys.sqlite")
	backend, err := sqlitestore.Open(keysPath)
	if err != nil {
		return nil, nil, nil, err
	}
	metadata, err := encryptedstore.New(backend)
	if err != nil {
		_ = backend.Close()
		return nil, nil, nil, err
	}
	vaultKeys, err := openVaultKeyEnvelopeStore(keysPath)
	if err != nil {
		_ = metadata.Close()
		return nil, nil, nil, err
	}
	if err := recoverDEKRotationFiles(dataDir, vaultKeys); err != nil {
		_ = vaultKeys.close()
		_ = metadata.Close()
		return nil, nil, nil, fmt.Errorf("recover interrupted DEK rotation: %w", err)
	}
	values, err := openVaultValueStore(filepath.Join(dataDir, vaultValueFilename))
	if err != nil {
		_ = vaultKeys.close()
		_ = metadata.Close()
		return nil, nil, nil, err
	}
	for _, filename := range []string{"keys.sqlite", "vault.sqlite"} {
		_ = os.Chmod(filepath.Join(dataDir, filename), 0o600)
	}
	return metadata, vaultKeys, values, nil
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
	var valueErr, vaultKeyErr, metadataErr error
	if s.values != nil {
		valueErr = s.values.close()
	}
	if s.vaultKeys != nil {
		vaultKeyErr = s.vaultKeys.close()
	}
	if s.metadata != nil {
		metadataErr = s.metadata.Close()
	}
	s.values = nil
	s.vaultKeys = nil
	s.metadata = nil
	s.selected = vaultReference{}
	return errors.Join(valueErr, vaultKeyErr, metadataErr)
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
	metadata, vaultKeys, values, err := openVaultStores(ref.Path)
	if err != nil {
		return vaultStatus{}, err
	}
	s.metadata = metadata
	s.vaultKeys = vaultKeys
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
	rootRef := store.KEKReference{
		CredentialID: rootCredential.ID,
		Salt:         rootSalt,
		RPID:         vaultRPID,
	}
	rootKEK, err := s.derive(auth, pin, rootRef, "root-kek")
	if err != nil {
		return vaultStatus{}, err
	}

	dek, err := randomVaultKey()
	if err != nil {
		return vaultStatus{}, err
	}
	if err := s.vaultKeys.put(ctx, 1, rootRef, dek, rootKEK); err != nil {
		return vaultStatus{}, fmt.Errorf("store wrapped vault DEK: %w", err)
	}
	if err := s.metadata.Initialize(ctx, rootRef, rootKEK); err != nil {
		_ = s.vaultKeys.delete(context.Background(), 1)
		return vaultStatus{}, fmt.Errorf("initialize encrypted key store: %w", err)
	}
	s.vaultDEK = dek
	s.rootKEK = rootKEK
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

	dek, err := s.vaultKeys.get(ctx, header.Revision, header.KEK, rootKEK)
	if errors.Is(err, errVaultKeyEnvelopeNotFound) {
		// Vaults created before the wrapped-DEK format stored a second FIDO
		// credential. Migrate that DEK once; later unlocks need only root KEK.
		record, getErr := s.metadata.Get(ctx, vaultDEKAlias)
		if getErr != nil {
			s.metadata.Lock()
			return vaultStatus{}, fmt.Errorf("load wrapped or legacy vault DEK: %w", getErr)
		}
		dek, err = s.derive(auth, pin, store.KEKReference{
			CredentialID: record.CredentialID,
			Salt:         record.Salt,
			RPID:         record.RPID,
		}, "vault-dek-migration")
		if err == nil {
			err = s.vaultKeys.put(ctx, header.Revision, header.KEK, dek, rootKEK)
		}
		if err == nil {
			// The envelope is durable before the legacy reference is removed.
			// Failure to remove it is harmless and can be retried later.
			_ = s.metadata.Delete(ctx, vaultDEKAlias)
		}
	}
	if err != nil {
		s.metadata.Lock()
		return vaultStatus{}, fmt.Errorf("unlock vault DEK: %w", err)
	}
	_ = s.vaultKeys.deleteExcept(ctx, header.Revision)
	s.vaultDEK = dek
	s.rootKEK = rootKEK
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
	header, err := s.metadata.Header(ctx)
	if err != nil {
		return vaultStatus{}, fmt.Errorf("load vault header before KEK rotation: %w", err)
	}
	if header.Revision == ^uint64(0) {
		return vaultStatus{}, errors.New("vault KEK revision is exhausted")
	}

	auth, device, err := s.openAuthenticator(devicePath)
	if err != nil {
		return vaultStatus{}, err
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
	nextRevision := header.Revision + 1
	if err := s.vaultKeys.put(ctx, nextRevision, nextRef, s.vaultDEK, nextKEK); err != nil {
		return vaultStatus{}, fmt.Errorf("stage wrapped vault DEK for KEK rotation: %w", err)
	}

	previousDevice := authenticatorInfo{
		Path:         s.selected.PreferredDevicePath,
		Product:      s.selected.PreferredDeviceProduct,
		Manufacturer: s.selected.PreferredDeviceManufacturer,
		VendorID:     s.selected.PreferredDeviceVendorID,
		ProductID:    s.selected.PreferredDeviceProductID,
	}
	if err := s.registry.rememberDevice(ctx, s.selected.Path, device); err != nil {
		_ = s.vaultKeys.delete(context.Background(), nextRevision)
		return vaultStatus{}, err
	}
	if err := s.metadata.RotateKEK(ctx, nextRef, nextKEK); err != nil {
		_ = s.vaultKeys.delete(context.Background(), nextRevision)
		_ = s.registry.rememberDevice(context.Background(), s.selected.Path, previousDevice)
		return vaultStatus{}, fmt.Errorf("rotate vault KEK: %w", err)
	}
	_ = s.vaultKeys.deleteExcept(ctx, nextRevision)
	s.rootKEK = nextKEK

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
	s.rootKEK = nil
	memguard.Purge()
}

func randomOperationID() string {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(id[:])
}
