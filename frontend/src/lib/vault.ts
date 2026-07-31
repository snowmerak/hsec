import * as WailsVault from "../../bindings/github.com/snowmerak/hsec/vaultservice";

export type VaultStatus = {
  initialized: boolean;
  unlocked: boolean;
  selected: boolean;
  vaultName: string;
  vaultPath: string;
};
export type VaultReference = {
  name: string;
  path: string;
  lastOpenedAt: string;
  available: boolean;
  preferredDevicePath: string;
  preferredDeviceProduct: string;
  preferredDeviceManufacturer: string;
  preferredDeviceVendorId: number;
  preferredDeviceProductId: number;
};
export type AuthenticatorInfo = {
  index: number;
  path: string;
  product: string;
  manufacturer: string;
  productId: number;
  vendorId: number;
  windowsHello: boolean;
};
export type VaultValueField = {name: string; value: string};
export type VaultValueDocument = {version: number; fields: VaultValueField[]};
export type VaultEntry = {
  alias: string;
  value: VaultValueDocument;
  revision: number;
  createdAt: string;
  updatedAt: string;
};
export type VaultEntrySummary = {
  alias: string;
  revision: number;
  updatedAt: string;
};

export interface VaultAPI {
  Status(): Promise<VaultStatus>;
  Vaults(): Promise<VaultReference[]>;
  AddVault(path: string): Promise<VaultReference>;
  SelectVault(path: string): Promise<VaultStatus>;
  CloseVault(): Promise<VaultStatus>;
  Authenticators(): Promise<AuthenticatorInfo[]>;
  Initialize(devicePath: string, pin: string): Promise<VaultStatus>;
  Unlock(devicePath: string, pin: string): Promise<VaultStatus>;
  Lock(): Promise<VaultStatus>;
  List(): Promise<VaultEntrySummary[]>;
  Get(alias: string): Promise<VaultEntry>;
  Create(alias: string, value: VaultValueDocument): Promise<VaultEntry>;
  Update(alias: string, value: VaultValueDocument, expectedRevision: number): Promise<VaultEntry>;
  Delete(alias: string, expectedRevision: number): Promise<void>;
}

const now = new Date().toISOString();
const previewMode = import.meta.env.DEV ? new URLSearchParams(window.location.search).get("preview") : null;
const personalPath = "/Users/example/Google Drive/My Drive/Vaults/personal";
const workPath = "/Users/example/Vaults/work";
let mockSelectedPath = previewMode === "launcher" ? "" : personalPath;
let mockUnlocked = previewMode === "unlocked";
let mockReferences: VaultReference[] = [
  {
    name: "personal",
    path: personalPath,
    lastOpenedAt: now,
    available: true,
    preferredDevicePath: "fido://yubikey-5",
    preferredDeviceProduct: "YubiKey 5 NFC",
    preferredDeviceManufacturer: "Yubico",
    preferredDeviceVendorId: 0x1050,
    preferredDeviceProductId: 0x0407,
  },
  {
    name: "work",
    path: workPath,
    lastOpenedAt: new Date(Date.now() - 86400000).toISOString(),
    available: true,
    preferredDevicePath: "",
    preferredDeviceProduct: "",
    preferredDeviceManufacturer: "",
    preferredDeviceVendorId: 0,
    preferredDeviceProductId: 0,
  },
];
const mockInitialized = new Map<string, boolean>([
  [personalPath, true],
  [workPath, true],
]);
const mockAuthenticators: AuthenticatorInfo[] = [
  {index: 0, path: "fido://yubikey-5", product: "YubiKey 5 NFC", manufacturer: "Yubico", vendorId: 0x1050, productId: 0x0407, windowsHello: false},
  {index: 1, path: "fido://solo-v2", product: "SoloKey v2", manufacturer: "SoloKeys", vendorId: 0x1209, productId: 0x5070, windowsHello: false},
];
let mockEntries: VaultEntry[] = [
  {alias: "개인 vault", value: {version: 1, fields: [{name: "사용자 이름", value: "snowmerak"}, {name: "비밀번호", value: "correct-horse-battery-staple"}, {name: "메모", value: "개인 계정"}]}, revision: 1, createdAt: now, updatedAt: now},
  {alias: "GitHub", value: {version: 1, fields: [{name: "사용자 이름", value: "snowmerak"}, {name: "API 토큰", value: "ghp_example_only"}]}, revision: 1, createdAt: now, updatedAt: now},
  {alias: "Google 계정", value: {version: 1, fields: [{name: "이메일", value: "hello@example.com"}, {name: "비밀번호", value: "browser-preview-only"}]}, revision: 1, createdAt: now, updatedAt: now},
  {alias: "이메일 (개인)", value: {version: 1, fields: [{name: "SMTP 비밀번호", value: "browser-preview-only"}]}, revision: 1, createdAt: now, updatedAt: now},
  {alias: "Notion API 키", value: {version: 1, fields: [{name: "토큰", value: "secret_example_only"}]}, revision: 1, createdAt: now, updatedAt: now},
];

function mockStatus(): VaultStatus {
  const reference = mockReferences.find((item) => item.path === mockSelectedPath);
  return {
    initialized: reference ? (mockInitialized.get(reference.path) ?? false) : false,
    unlocked: Boolean(reference && mockUnlocked),
    selected: Boolean(reference),
    vaultName: reference?.name ?? "",
    vaultPath: reference?.path ?? "",
  };
}

const mockVault: VaultAPI = {
  async Status() {
    return mockStatus();
  },
  async Vaults() {
    return mockReferences.map((reference) => ({...reference}));
  },
  async AddVault(path) {
    const existing = mockReferences.find((item) => item.path === path);
    if (existing) return {...existing};
    const reference: VaultReference = {
      name: path.split("/").filter(Boolean).at(-1) ?? "vault",
      path,
      lastOpenedAt: "",
      available: true,
      preferredDevicePath: "",
      preferredDeviceProduct: "",
      preferredDeviceManufacturer: "",
      preferredDeviceVendorId: 0,
      preferredDeviceProductId: 0,
    };
    mockReferences = [...mockReferences, reference];
    mockInitialized.set(path, false);
    return {...reference};
  },
  async SelectVault(path) {
    if (!mockReferences.some((item) => item.path === path)) throw new Error("vault reference not found");
    mockSelectedPath = path;
    mockUnlocked = false;
    return mockStatus();
  },
  async CloseVault() {
    mockSelectedPath = "";
    mockUnlocked = false;
    return mockStatus();
  },
  async Authenticators() {
    return mockAuthenticators.map((device) => ({...device}));
  },
  async Initialize(devicePath) {
    if (!mockSelectedPath || !mockAuthenticators.some((device) => device.path === devicePath)) throw new Error("select a FIDO2 security key");
    mockInitialized.set(mockSelectedPath, true);
    mockUnlocked = true;
    return mockStatus();
  },
  async Unlock(devicePath) {
    if (!mockAuthenticators.some((device) => device.path === devicePath)) throw new Error("select a FIDO2 security key");
    mockUnlocked = true;
    return mockStatus();
  },
  async Lock() {
    mockUnlocked = false;
    return mockStatus();
  },
  async List() {
    return mockEntries.map(({alias, revision, updatedAt}) => ({alias, revision, updatedAt}));
  },
  async Get(alias) {
    const entry = mockEntries.find((item) => item.alias === alias);
    if (!entry) throw new Error("entry not found");
    return {...entry, value: {version: entry.value.version, fields: entry.value.fields.map((field) => ({...field}))}};
  },
  async Create(alias, value) {
    if (mockEntries.some((item) => item.alias === alias)) throw new Error("entry already exists");
    const storedValue = {version: value.version, fields: value.fields.map((field) => ({...field}))};
    const entry = {alias, value: storedValue, revision: 1, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()};
    mockEntries = [...mockEntries, entry];
    return {...entry, value: {version: entry.value.version, fields: entry.value.fields.map((field) => ({...field}))}};
  },
  async Update(alias, value, expectedRevision) {
    const current = mockEntries.find((item) => item.alias === alias);
    if (!current || current.revision !== expectedRevision) throw new Error("entry changed");
    const storedValue = {version: value.version, fields: value.fields.map((field) => ({...field}))};
    const updated = {...current, value: storedValue, revision: current.revision + 1, updatedAt: new Date().toISOString()};
    mockEntries = mockEntries.map((item) => item.alias === alias ? updated : item);
    return {...updated, value: {version: updated.value.version, fields: updated.value.fields.map((field) => ({...field}))}};
  },
  async Delete(alias, expectedRevision) {
    const current = mockEntries.find((item) => item.alias === alias);
    if (!current || current.revision !== expectedRevision) throw new Error("entry changed");
    mockEntries = mockEntries.filter((item) => item.alias !== alias);
  },
};

function normalizeEntry(entry: Awaited<ReturnType<typeof WailsVault.Get>>): VaultEntry {
  return {
    alias: entry.alias,
    value: {
      version: entry.value.version,
      fields: (entry.value.fields ?? []).map((field) => ({name: field.name, value: field.value})),
    },
    revision: entry.revision,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
  };
}

const wailsVault: VaultAPI = {
  async Status() {
    return WailsVault.Status();
  },
  async Vaults() {
    return (await WailsVault.Vaults()) ?? [];
  },
  async AddVault(path) {
    return WailsVault.AddVault(path);
  },
  async SelectVault(path) {
    return WailsVault.SelectVault(path);
  },
  async CloseVault() {
    return WailsVault.CloseVault();
  },
  async Authenticators() {
    return (await WailsVault.Authenticators()) ?? [];
  },
  async Initialize(devicePath, pin) {
    return WailsVault.Initialize(devicePath, pin);
  },
  async Unlock(devicePath, pin) {
    return WailsVault.Unlock(devicePath, pin);
  },
  async Lock() {
    return WailsVault.Lock();
  },
  async List() {
    return (await WailsVault.List()) ?? [];
  },
  async Get(alias) {
    return normalizeEntry(await WailsVault.Get(alias));
  },
  async Create(alias, value) {
    return normalizeEntry(await WailsVault.Create(alias, value));
  },
  async Update(alias, value, expectedRevision) {
    return normalizeEntry(await WailsVault.Update(alias, value, expectedRevision));
  },
  async Delete(alias, expectedRevision) {
    return WailsVault.Delete(alias, expectedRevision);
  },
};

export const isPreview = previewMode !== null;
export const vault: VaultAPI = isPreview ? mockVault : wailsVault;
