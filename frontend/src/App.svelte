<script lang="ts">
  import {onMount} from "svelte";
  import {Dialogs, Events} from "@wailsio/runtime";
  import Icon from "./lib/Icon.svelte";
  import {
    defaultDeviceLabel,
    isPreview,
    vault,
    type AuthenticatorInfo,
    type CredentialSlot,
    type VaultEntry,
    type VaultEntrySummary,
    type VaultReference,
    type VaultStatus,
    type VaultValueField,
  } from "./lib/vault";

  type Toast = {
    id: string;
    tone: "info" | "success" | "danger";
    title: string;
    message: string;
    persistent?: boolean;
  };
  type FidoEvent = {operationId: string; phase: string; message: string};
  type DEKRotationProgress = {
    phase: "ready" | "copying" | "switching" | "completed" | "failed";
    completed: number;
    total: number;
    percent: number;
    message: string;
  };
  type Confirmation = {
    title: string;
    message: string;
    confirmLabel: string;
    destructive?: boolean;
    action: () => void | Promise<void>;
  };

  let status: VaultStatus | null = $state(null);
  let vaultReferences: VaultReference[] = $state([]);
  let authenticators: AuthenticatorInfo[] = $state([]);
  let credentialSlots: CredentialSlot[] = $state([]);
  let selectedSlotId = $state("");
  let selectedDevicePath = $state("");
  let loadingDevices = $state(false);
  let entries: VaultEntrySummary[] = $state([]);
  let selected: VaultEntry | null = $state(null);
  let alias = $state("");
  let fields: VaultValueField[] = $state([]);
  let revealed: boolean[] = $state([]);
  let pin = $state("");
  let kekRotationOpen = $state(false);
  let rotationDevicePath = $state("");
  let rotationPin = $state("");
  let deviceManagerOpen = $state(false);
  let addDevicePath = $state("");
  let addDeviceLabel = $state("");
  let addDevicePin = $state("");
  let dekRotationOpen = $state(false);
  let dekRotationRunning = $state(false);
  let dekProgress: DEKRotationProgress = $state({
    phase: "ready",
    completed: 0,
    total: 0,
    percent: 0,
    message: "모든 항목을 새 키로 다시 암호화합니다.",
  });
  let busy = $state(false);
  let dirty = $state(false);
  let creating = $state(false);
  let toasts: Toast[] = $state([]);
  let pendingConfirmation: Confirmation | null = $state(null);

  onMount(() => {
    const offWaiting = Events.On("vault:fido-waiting", (event) => {
      const data = event.data as FidoEvent;
      toasts = [
        ...toasts.filter((toast) => toast.id !== data.operationId),
        {
          id: data.operationId,
          tone: "info",
          title: "보안 키를 터치해 주세요",
          message: data.message,
          persistent: true,
        },
      ];
    });
    const offResolved = Events.On("vault:fido-resolved", (event) => {
      const data = event.data as FidoEvent;
      toasts = toasts.filter((toast) => toast.id !== data.operationId);
    });
    const offDEKProgress = Events.On("vault:dek-rotation-progress", (event) => {
      dekProgress = event.data as DEKRotationProgress;
    });
    if (import.meta.env.DEV && new URLSearchParams(window.location.search).get("toast") === "fido") {
      toasts = [{
        id: "preview-fido",
        tone: "info",
        title: "보안 키를 터치해 주세요",
        message: "계속하려면 FIDO2 보안 키의 버튼을 누르세요.",
        persistent: true,
      }];
    }
    void loadStatus();
    return () => {
      offWaiting();
      offResolved();
      offDEKProgress();
    };
  });

  async function loadStatus() {
    try {
      await refreshVaultReferences();
      status = await vault.Status();
      if (status.selected) await refreshCredentialSlots();
      if (status.unlocked) {
        await refreshEntries();
      } else if (status.selected) {
        await refreshAuthenticators();
      }
    } catch (error) {
      showError(error);
      status = {initialized: false, unlocked: false, selected: false, vaultName: "", vaultPath: ""};
    }
  }

  async function refreshVaultReferences() {
    vaultReferences = await vault.Vaults();
  }

  async function chooseVaultFolder() {
    busy = true;
    try {
      const path = isPreview
        ? "/Users/example/Google Drive/My Drive/Vaults/new-personal"
        : await Dialogs.OpenFile({
            CanChooseDirectories: true,
            CanChooseFiles: false,
            CanCreateDirectories: true,
            ResolvesAliases: true,
            Title: "vault 폴더 선택",
            Message: "기존 vault 폴더를 선택하거나 새 폴더를 만들어 주세요.",
            ButtonText: "이 폴더 사용",
          });
      if (!path) return;
      const reference = await vault.AddVault(path);
      await refreshVaultReferences();
      await openVault(reference.path);
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function openVault(path: string) {
    busy = true;
    try {
      status = await vault.SelectVault(path);
      entries = [];
      selected = null;
      await refreshVaultReferences();
      await refreshCredentialSlots();
      await refreshAuthenticators();
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function refreshAuthenticators() {
    loadingDevices = true;
    try {
      authenticators = await vault.Authenticators();
      const currentVault = vaultReferences.find((reference) => reference.path === status?.vaultPath);
      const preferred = authenticators.find((device) =>
        device.path === currentVault?.preferredDevicePath
        || (
          currentVault?.preferredDeviceVendorId !== 0
          && device.vendorId === currentVault?.preferredDeviceVendorId
          && device.productId === currentVault.preferredDeviceProductId
          && device.product === currentVault.preferredDeviceProduct
        ),
      );
      selectedDevicePath = preferred?.path ?? (authenticators.length === 1 ? authenticators[0].path : "");
    } catch (error) {
      authenticators = [];
      selectedDevicePath = "";
      showError(error);
    } finally {
      loadingDevices = false;
    }
  }

  async function initializeOrUnlock() {
    if (!status || busy) return;
    if (!selectedDevicePath) {
      showToast("danger", "보안 키를 선택해 주세요", "연결된 FIDO2 장치 중 이 vault에 사용할 장치를 선택해 주세요.");
      return;
    }
    busy = true;
    try {
      const wasInitialized = status.initialized;
      status = wasInitialized
        ? credentialSlots.length > 0
          ? await vault.UnlockSlot(selectedSlotId, selectedDevicePath, pin)
          : await vault.Unlock(selectedDevicePath, pin)
        : await vault.Initialize(selectedDevicePath, pin);
      pin = "";
      await refreshCredentialSlots();
      await refreshEntries();
      showToast("success", wasInitialized ? "vault가 열렸습니다" : "vault가 준비됐습니다", "보안 키로 암호화 키를 안전하게 유도했습니다.");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function refreshCredentialSlots() {
    credentialSlots = await vault.CredentialSlots();
    if (!credentialSlots.some((slot) => slot.id === selectedSlotId)) {
      selectedSlotId = credentialSlots[0]?.id ?? "";
    }
  }

  async function openKEKRotation() {
    if (busy) return;
    kekRotationOpen = true;
    rotationPin = "";
    rotationDevicePath = "";
    await refreshRotationAuthenticators();
  }

  async function refreshRotationAuthenticators() {
    loadingDevices = true;
    try {
      authenticators = await vault.Authenticators();
      const currentVault = vaultReferences.find((reference) => reference.path === status?.vaultPath);
      const selected = authenticators.find((device) => device.path === rotationDevicePath);
      const preferred = authenticators.find((device) =>
        device.path === currentVault?.preferredDevicePath
        || (
          currentVault?.preferredDeviceVendorId !== 0
          && device.vendorId === currentVault?.preferredDeviceVendorId
          && device.productId === currentVault.preferredDeviceProductId
          && device.product === currentVault.preferredDeviceProduct
        ),
      );
      rotationDevicePath = selected?.path ?? preferred?.path ?? (authenticators.length === 1 ? authenticators[0].path : "");
    } catch (error) {
      authenticators = [];
      rotationDevicePath = "";
      showError(error);
    } finally {
      loadingDevices = false;
    }
  }

  function closeKEKRotation() {
    if (busy) return;
    kekRotationOpen = false;
    rotationDevicePath = "";
    rotationPin = "";
  }

  async function rotateKEK() {
    if (!rotationDevicePath || busy) return;
    busy = true;
    try {
      status = await vault.RotateKEK(rotationDevicePath, rotationPin);
      rotationPin = "";
      kekRotationOpen = false;
      await refreshVaultReferences();
      showToast("success", "KEK를 회전했습니다", "활성 장치 슬롯의 credential로 같은 vault DEK를 다시 보호했습니다.");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  function openDEKRotation() {
    if (busy) return;
    dekProgress = {
      phase: "ready",
      completed: 0,
      total: entries.length,
      percent: 0,
      message: "기존 DB는 완료 시점까지 그대로 유지됩니다.",
    };
    dekRotationOpen = true;
  }

  function closeDEKRotation() {
    if (dekRotationRunning) return;
    dekRotationOpen = false;
  }

  async function rotateDEK() {
    if (busy || dekRotationRunning) return;
    busy = true;
    dekRotationRunning = true;
    try {
      status = await vault.RotateDEK();
      await refreshCredentialSlots();
      dekRotationOpen = false;
      showToast("success", "DEK를 회전했습니다", `${entries.length}개 항목을 새 키로 다시 암호화했습니다.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      dekProgress = {...dekProgress, phase: "failed", message};
      showError(error);
    } finally {
      dekRotationRunning = false;
      busy = false;
    }
  }

  async function openDeviceManager() {
    if (busy) return;
    deviceManagerOpen = true;
    addDevicePin = "";
    await Promise.all([refreshCredentialSlots(), refreshRotationAuthenticators()]);
    const device = authenticators.find((item) => item.path === rotationDevicePath) ?? authenticators[0];
    addDevicePath = device?.path ?? "";
    addDeviceLabel = device ? defaultDeviceLabel(device) : "";
  }

  function closeDeviceManager() {
    if (busy) return;
    deviceManagerOpen = false;
    addDevicePath = "";
    addDeviceLabel = "";
    addDevicePin = "";
  }

  function chooseAddDevice(device: AuthenticatorInfo) {
    addDevicePath = device.path;
    addDeviceLabel = defaultDeviceLabel(device);
  }

  async function refreshDeviceManagerAuthenticators() {
    await refreshRotationAuthenticators();
    const current = authenticators.find((device) => device.path === addDevicePath);
    if (!current) {
      const next = authenticators[0];
      addDevicePath = next?.path ?? "";
      addDeviceLabel = next ? defaultDeviceLabel(next) : "";
    }
  }

  async function addCredentialSlot() {
    if (!addDevicePath || busy) return;
    busy = true;
    try {
      const slot = await vault.AddCredentialSlot(addDevicePath, addDevicePin, addDeviceLabel);
      addDevicePin = "";
      await refreshCredentialSlots();
      showToast("success", "장치를 추가했습니다", `“${slot.label}” 레이블로 이 vault를 열 수 있습니다.`);
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  function removeCredentialSlot(slot: CredentialSlot) {
    requestConfirmation({
      title: "장치 슬롯 삭제",
      message: `“${slot.label}” 슬롯을 삭제합니다. 이 credential로는 더 이상 vault를 열 수 없습니다.`,
      confirmLabel: "슬롯 삭제",
      destructive: true,
      action: async () => {
        busy = true;
        try {
          await vault.DeleteCredentialSlot(slot.id);
          await refreshCredentialSlots();
          showToast("success", "장치 슬롯을 삭제했습니다", `“${slot.label}”의 접근 권한을 제거했습니다.`);
        } catch (error) {
          showError(error);
        } finally {
          busy = false;
        }
      },
    });
  }

  async function refreshEntries(preferredAlias?: string) {
    entries = await vault.List();
    const nextAlias = preferredAlias ?? selected?.alias ?? entries[0]?.alias;
    if (nextAlias && entries.some((entry) => entry.alias === nextAlias)) {
      await loadEntry(nextAlias);
    } else {
      startNew();
    }
  }

  async function selectEntry(nextAlias: string) {
    if (dirty) {
      requestConfirmation({
        title: "변경 사항 버리기",
        message: "저장하지 않은 변경 사항을 버리고 다른 항목을 열까요?",
        confirmLabel: "버리고 열기",
        action: () => loadEntry(nextAlias),
      });
      return;
    }
    await loadEntry(nextAlias);
  }

  async function loadEntry(nextAlias: string) {
    busy = true;
    try {
      selected = await vault.Get(nextAlias);
      alias = selected.alias;
      fields = selected.value.fields.map((field) => ({...field}));
      revealed = fields.map(() => false);
      creating = false;
      dirty = false;
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  function startNew() {
    if (dirty) {
      requestConfirmation({
        title: "변경 사항 버리기",
        message: "저장하지 않은 변경 사항을 버리고 새 항목을 만들까요?",
        confirmLabel: "버리고 계속",
        action: resetNewEntry,
      });
      return;
    }
    resetNewEntry();
  }

  function resetNewEntry() {
    selected = null;
    alias = "";
    fields = [{name: "", value: ""}];
    revealed = [false];
    creating = true;
    dirty = false;
  }

  async function saveEntry() {
    if (!alias) {
      showToast("danger", "이름이 필요합니다", "UUID 대신 사용할 alias를 그대로 입력해 주세요.");
      return;
    }
    const missingName = fields.findIndex((field) => !field.name);
    if (missingName >= 0) {
      showToast("danger", "필드 이름이 필요합니다", `${missingName + 1}번째 행의 필드 이름을 입력해 주세요.`);
      return;
    }
    busy = true;
    try {
      const value = {version: 1, fields: fields.map((field) => ({...field}))};
      const saved = creating
        ? await vault.Create(alias, value)
        : await vault.Update(selected!.alias, value, selected!.revision);
      await refreshEntries(saved.alias);
      showToast("success", "저장했습니다", `"${saved.alias}"의 암호문을 갱신했습니다.`);
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  function deleteEntry() {
    if (!selected) return;
    const entry = selected;
    requestConfirmation({
      title: "항목 삭제",
      message: `"${entry.alias}"을 vault에서 삭제합니다. 이 작업은 되돌릴 수 없습니다.`,
      confirmLabel: "삭제",
      destructive: true,
      action: () => performDelete(entry),
    });
  }

  async function performDelete(entry: VaultEntry) {
    busy = true;
    try {
      await vault.Delete(entry.alias, entry.revision);
      selected = null;
      dirty = false;
      await refreshEntries();
      showToast("success", "삭제했습니다", "선택한 항목을 vault에서 제거했습니다.");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function lockVault() {
    if (dirty) {
      requestConfirmation({
        title: "vault 잠그기",
        message: "저장하지 않은 변경 사항을 버리고 vault를 잠글까요?",
        confirmLabel: "버리고 잠그기",
        action: performLock,
      });
      return;
    }
    await performLock();
  }

  async function performLock() {
    status = await vault.Lock();
    entries = [];
    selected = null;
    alias = "";
    fields = [];
    revealed = [];
    dirty = false;
    await refreshVaultReferences();
    await refreshCredentialSlots();
    await refreshAuthenticators();
  }

  function closeVault() {
    if (dirty) {
      requestConfirmation({
        title: "vault 목록으로 이동",
        message: "저장하지 않은 변경 사항을 버리고 현재 vault를 닫을까요?",
        confirmLabel: "버리고 닫기",
        action: performCloseVault,
      });
      return;
    }
    void performCloseVault();
  }

  async function performCloseVault() {
    status = await vault.CloseVault();
    entries = [];
    selected = null;
    alias = "";
    fields = [];
    revealed = [];
    authenticators = [];
    credentialSlots = [];
    selectedSlotId = "";
    selectedDevicePath = "";
    dirty = false;
    await refreshVaultReferences();
  }

  function requestConfirmation(confirmation: Confirmation) {
    pendingConfirmation = confirmation;
  }

  function closeConfirmation() {
    if (!busy) pendingConfirmation = null;
  }

  async function acceptConfirmation() {
    const action = pendingConfirmation?.action;
    if (!action) return;
    pendingConfirmation = null;
    await action();
  }

  function markDirty() {
    dirty = true;
  }

  function addField() {
    fields = [...fields, {name: "", value: ""}];
    revealed = [...revealed, false];
    dirty = true;
  }

  function removeField(index: number) {
    fields = fields.filter((_, fieldIndex) => fieldIndex !== index);
    revealed = revealed.filter((_, fieldIndex) => fieldIndex !== index);
    dirty = true;
  }

  function toggleField(index: number) {
    revealed[index] = !revealed[index];
  }

  async function copyField(index: number) {
    try {
      await navigator.clipboard.writeText(fields[index].value);
      showToast("success", "복사했습니다", `"${fields[index].name}" 값을 클립보드에 복사했습니다.`);
    } catch (error) {
      showError(error);
    }
  }

  function showError(error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    showToast("danger", "작업을 완료하지 못했습니다", message);
  }

  function showToast(tone: Toast["tone"], title: string, message: string) {
    const id = `${Date.now()}-${Math.random()}`;
    toasts = [...toasts, {id, tone, title, message}];
    window.setTimeout(() => {
      toasts = toasts.filter((toast) => toast.id !== id);
    }, 3600);
  }

  function formatLastOpened(value: string) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "최근 사용";
    return new Intl.DateTimeFormat("ko-KR", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  }

  function formatUSBID(vendorID: number, productID: number) {
    const hex = (value: number) => (value & 0xffff).toString(16).padStart(4, "0").toUpperCase();
    return `${hex(vendorID)}:${hex(productID)}`;
  }
</script>

<svelte:window onkeydown={(event) => {
  if (event.key === "Escape" && deviceManagerOpen) {
    event.preventDefault();
    closeDeviceManager();
    return;
  }
  if (event.key === "Escape" && kekRotationOpen) {
    event.preventDefault();
    closeKEKRotation();
    return;
  }
  if (event.key === "Escape" && dekRotationOpen) {
    event.preventDefault();
    closeDEKRotation();
    return;
  }
  if (event.key === "Escape" && pendingConfirmation) {
    event.preventDefault();
    closeConfirmation();
    return;
  }
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s" && status?.unlocked) {
    event.preventDefault();
    void saveEntry();
  }
}} />

{#if status === null}
  <main class="state-screen" aria-busy="true">
    <div class="brand-lockup"><span class="brand-mark">h</span><strong>hsec</strong></div>
    <div class="mp-spinner" aria-label="vault 상태 확인 중"></div>
  </main>
{:else if !status.selected}
  <main class="state-screen vault-launcher-screen">
    <section class="vault-launcher" aria-labelledby="vault-launcher-title">
      <div class="vault-launcher-header">
        <div>
          <p class="section-eyebrow">PORTABLE VAULT</p>
          <h1 id="vault-launcher-title">vault 선택</h1>
          <p>동기화할 폴더를 선택하거나 최근에 열었던 vault를 이어서 사용하세요.</p>
        </div>
        <button class="mp-button mp-button--primary" disabled={busy} onclick={chooseVaultFolder}>
          <Icon name="folder-plus"/>
          폴더 선택
        </button>
      </div>

      <div class="recent-vaults">
        <div class="recent-vaults-heading">
          <span class="mp-field__label">최근 vault</span>
          <span>{vaultReferences.length}개</span>
        </div>
        <div class="vault-reference-list">
          {#each vaultReferences as reference (reference.path)}
            <button
              class="mp-card vault-reference"
              disabled={busy || !reference.available}
              onclick={() => openVault(reference.path)}
            >
              <span class="vault-reference-icon"><Icon name="folder" size={22}/></span>
              <span class="vault-reference-copy">
                <strong>{reference.name}</strong>
                <span class="vault-reference-path">{reference.path}</span>
              </span>
              <span class="vault-reference-meta">
                {reference.available
                  ? reference.lastOpenedAt ? formatLastOpened(reference.lastOpenedAt) : "아직 열지 않음"
                  : "폴더를 찾을 수 없음"}
              </span>
              <Icon name="chevron-right" size={18}/>
            </button>
          {:else}
            <div class="mp-card vault-reference-empty">
              <Icon name="folder" size={24}/>
              <strong>등록된 vault가 없습니다</strong>
              <span>Google Drive, iCloud Drive 또는 로컬 폴더를 선택해 시작하세요.</span>
            </div>
          {/each}
        </div>
      </div>
      <p class="launcher-note">최근 목록에는 경로와 장치 힌트만 저장하며 PIN과 암호화 키는 저장하지 않습니다.</p>
    </section>
  </main>
{:else if !status.unlocked}
  <main class="state-screen">
    <form
      class="unlock-panel"
      aria-labelledby="unlock-title"
      onsubmit={(event) => {
        event.preventDefault();
        void initializeOrUnlock();
      }}
    >
      <div class="unlock-heading">
        <div class="unlock-symbol"><Icon name="shield" size={28}/></div>
        <button class="mp-button mp-button--ghost mp-button--sm" type="button" onclick={closeVault}>
          <Icon name="chevron-left" size={16}/>
          vault 목록
        </button>
      </div>
      <div class="unlock-copy">
        <p class="section-eyebrow">{status.initialized ? "UNLOCK VAULT" : "CREATE VAULT"}</p>
        <h1 id="unlock-title">{status.initialized ? `${status.vaultName} 열기` : `${status.vaultName} 만들기`}</h1>
        <span class="selected-vault-path">{status.vaultPath}</span>
      </div>

      {#if status.initialized && credentialSlots.length > 0}
        <fieldset class="authenticator-picker">
          <legend class="mp-field__label">사용할 장치 레이블</legend>
          <div class="authenticator-list" role="radiogroup" aria-label="credential 슬롯">
            {#each credentialSlots as slot (slot.id)}
              <label class="authenticator-option" class:authenticator-option--selected={selectedSlotId === slot.id}>
                <input type="radio" name="credential-slot" value={slot.id} bind:group={selectedSlotId}/>
                <span class="authenticator-icon"><Icon name="key" size={19}/></span>
                <span class="authenticator-copy">
                  <strong>{slot.label}</strong>
                  <span>이 레이블에 등록한 장치를 연결하세요</span>
                </span>
              </label>
            {/each}
          </div>
        </fieldset>
      {/if}

      <fieldset class="authenticator-picker">
        <div class="authenticator-picker-heading">
          <legend class="mp-field__label">FIDO2 보안 키</legend>
          <button class="mp-button mp-button--ghost mp-button--sm" type="button" disabled={loadingDevices || busy} onclick={refreshAuthenticators}>
            <Icon name="refresh" size={15}/>
            새로고침
          </button>
        </div>
        {#if loadingDevices}
          <div class="authenticator-empty"><span class="mp-spinner"></span>연결된 장치를 찾는 중…</div>
        {:else if authenticators.length === 0}
          <div class="authenticator-empty">연결된 FIDO2 보안 키가 없습니다.</div>
        {:else}
          <div class="authenticator-list" role="radiogroup" aria-label="FIDO2 보안 키">
            {#each authenticators as device (device.path)}
              <label class="authenticator-option" class:authenticator-option--selected={selectedDevicePath === device.path}>
                <input type="radio" name="authenticator" value={device.path} bind:group={selectedDevicePath}/>
                <span class="authenticator-icon"><Icon name="usb" size={19}/></span>
                <span class="authenticator-copy">
                  <strong>{device.product || "FIDO2 보안 키"}</strong>
                  <span>{device.windowsHello ? "Windows Security에서 장치를 선택합니다" : device.manufacturer || "제조사 정보 없음"}</span>
                </span>
                {#if !device.windowsHello}
                  <span class="authenticator-id">{formatUSBID(device.vendorId, device.productId)}</span>
                {/if}
              </label>
            {/each}
          </div>
        {/if}
      </fieldset>

      <label class="mp-field">
        <span class="mp-field__label">보안 키 PIN <span class="optional">(선택)</span></span>
        <input class="mp-input" name="pin" type="password" bind:value={pin} autocomplete="off" placeholder="플랫폼에서 직접 처리하면 비워 두세요"/>
      </label>
      <button class="mp-button mp-button--primary unlock-action" type="submit" disabled={busy || loadingDevices || authenticators.length === 0 || (status.initialized && credentialSlots.length > 0 && !selectedSlotId)}>
        <Icon name="key"/>
        {busy ? "보안 키 기다리는 중…" : status.initialized ? "vault 열기" : "vault 만들기"}
      </button>
      <p class="security-note">PIN은 이 작업에만 사용되며 저장하지 않습니다.</p>
    </form>
  </main>
{:else}
  <main class="vault-shell">
    <aside class="mp-sidebar vault-sidebar">
      <div class="sidebar-top">
        <div class="brand-lockup"><span class="brand-mark">h</span><strong>hsec</strong></div>
        <button class="mp-button mp-button--primary new-button" onclick={startNew}>
          <Icon name="plus"/>
          새 항목
        </button>
      </div>

      <nav class="entry-nav" aria-label="vault 항목">
        {#each entries as entry (entry.alias)}
          <button
            class="mp-sidebar__item entry-row"
            aria-current={!creating && selected?.alias === entry.alias ? "page" : undefined}
            onclick={() => selectEntry(entry.alias)}
          >
            <span>{entry.alias}</span>
          </button>
        {:else}
          <div class="sidebar-empty">아직 저장한 항목이 없습니다.</div>
        {/each}
      </nav>

      <div class="sidebar-actions">
        <button class="mp-button mp-button--ghost rotation-button" disabled={busy} title="장치 관리" onclick={openDeviceManager}>
          <Icon name="usb"/>
          <span class="sidebar-action-label">장치 관리</span>
        </button>
        <button class="mp-button mp-button--ghost rotation-button" disabled={busy} title="DEK 회전" onclick={openDEKRotation}>
          <Icon name="refresh"/>
          <span class="sidebar-action-label">DEK 회전</span>
        </button>
        <button class="mp-button mp-button--ghost rotation-button" disabled={busy} title="KEK 회전" onclick={openKEKRotation}>
          <Icon name="key"/>
          <span class="sidebar-action-label">KEK 회전</span>
        </button>
        <button class="mp-button mp-button--ghost lock-button" disabled={busy} title="vault 잠그기" onclick={lockVault}>
          <Icon name="lock"/>
          <span class="sidebar-action-label">잠그기</span>
        </button>
      </div>
    </aside>

    <section class="editor">
      <header class="editor-header" class:editor-header--creating={creating}>
        <div class="editor-title-block">
          {#if creating}
            <h1>새 항목</h1>
            <label class="mp-card alias-card">
              <span class="mp-field__label">항목 이름</span>
              <input
                class="mp-input alias-input"
                aria-label="새 항목 이름"
                bind:value={alias}
                oninput={markDirty}
                placeholder="이름을 입력하세요"
              />
            </label>
          {:else}
            <p class="editor-context">개인 vault</p>
            <h1>{alias}</h1>
          {/if}
        </div>
        {#if dirty}<span class="dirty-indicator">변경됨</span>{/if}
      </header>

      <div class="editor-body">
        <section class="mp-card secret-card" aria-labelledby="secret-field-label">
          <div class="value-table-header">
            <div>
              <span class="mp-field__label" id="secret-field-label">값</span>
              <span class="value-table-meta">{fields.length}개 필드</span>
            </div>
            <button class="mp-button mp-button--secondary mp-button--sm" onclick={addField}>
              <Icon name="plus" size={16}/>
              행 추가
            </button>
          </div>

          <div class="table-shell value-table-shell">
            <div class="table-scroll">
              <table class="mp-table mp-table--dense value-table">
                <thead>
                  <tr>
                    <th scope="col">필드</th>
                    <th scope="col">값</th>
                    <th scope="col" class="mp-table__action-cell">작업</th>
                  </tr>
                </thead>
                <tbody>
                  {#each fields as field, index}
                    <tr>
                      <td data-label="필드">
                        <input
                          class="mp-input table-input field-name-input"
                          aria-label={`${index + 1}번째 필드 이름`}
                          bind:value={field.name}
                          oninput={markDirty}
                          placeholder="예: 비밀번호"
                          autocomplete="off"
                        />
                      </td>
                      <td data-label="값">
                        <input
                          class="mp-input table-input field-value-input"
                          aria-label={`${index + 1}번째 필드 값`}
                          type={revealed[index] ? "text" : "password"}
                          bind:value={field.value}
                          oninput={markDirty}
                          placeholder="값을 입력하세요"
                          autocomplete="off"
                          spellcheck="false"
                        />
                      </td>
                      <td data-label="작업" class="mp-table__action-cell">
                        <div class="field-actions">
                          <button
                            class="mp-button mp-button--icon mp-button--sm"
                            aria-label={`${index + 1}번째 필드 값 ${revealed[index] ? "숨기기" : "보기"}`}
                            title={revealed[index] ? "숨기기" : "보기"}
                            onclick={() => toggleField(index)}
                          ><Icon name={revealed[index] ? "eye-off" : "eye"} size={16}/></button>
                          <button
                            class="mp-button mp-button--icon mp-button--sm"
                            aria-label={`${index + 1}번째 필드 값 복사`}
                            title="복사"
                            onclick={() => copyField(index)}
                          ><Icon name="copy" size={16}/></button>
                          <button
                            class="mp-button mp-button--icon mp-button--danger mp-button--sm"
                            aria-label={`${index + 1}번째 필드 삭제`}
                            title="삭제"
                            onclick={() => removeField(index)}
                          ><Icon name="trash" size={16}/></button>
                        </div>
                      </td>
                    </tr>
                  {:else}
                    <tr class="value-table-empty">
                      <td colspan="3">저장할 필드가 없습니다. 행을 추가해 주세요.</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <div class="editor-actions">
          <button class="mp-button mp-button--primary" disabled={busy || (!dirty && !creating)} onclick={saveEntry}>
            <Icon name="save"/>
            저장
          </button>
          {#if !creating}
            <button class="mp-button mp-button--danger delete-button" disabled={busy} onclick={deleteEntry}>
              <Icon name="trash"/>
              삭제
            </button>
          {/if}
        </div>
      </div>
    </section>
  </main>
{/if}

{#if deviceManagerOpen}
  <div class="confirmation-backdrop" role="presentation">
    <div class="mp-card rotation-dialog device-manager-dialog" role="dialog" aria-modal="true" aria-labelledby="device-manager-title">
      <div class="rotation-form">
        <div class="rotation-heading">
          <div class="confirmation-icon"><Icon name="usb" size={22}/></div>
          <div class="confirmation-copy">
            <h2 id="device-manager-title">장치 관리</h2>
            <p>레이블을 보고 슬롯을 고릅니다. 실제 장치는 잠금 해제할 때 사용자가 선택합니다.</p>
          </div>
        </div>

        <section class="credential-slot-section" aria-labelledby="registered-slots-title">
          <div class="authenticator-picker-heading">
            <h3 id="registered-slots-title" class="mp-field__label">등록된 슬롯</h3>
            <span>{credentialSlots.length}개</span>
          </div>
          <div class="credential-slot-list">
            {#each credentialSlots as slot (slot.id)}
              <div class="credential-slot-row">
                <span class="authenticator-icon"><Icon name="key" size={18}/></span>
                <span class="authenticator-copy">
                  <strong>{slot.label}</strong>
                  <span>{slot.active ? "현재 vault를 연 슬롯" : "다음 잠금 해제부터 선택 가능"}</span>
                </span>
                {#if slot.active}
                  <span class="slot-badge">사용 중</span>
                {:else}
                  <button class="mp-button mp-button--ghost mp-button--sm" type="button" disabled={busy} onclick={() => removeCredentialSlot(slot)}>
                    <Icon name="trash" size={15}/>
                    삭제
                  </button>
                {/if}
              </div>
            {/each}
          </div>
        </section>

        <form class="credential-add-form" onsubmit={(event) => { event.preventDefault(); void addCredentialSlot(); }}>
          <div class="authenticator-picker-heading">
            <h3 class="mp-field__label">새 장치 추가</h3>
            <button class="mp-button mp-button--ghost mp-button--sm" type="button" disabled={loadingDevices || busy} onclick={refreshDeviceManagerAuthenticators}>
              <Icon name="refresh" size={15}/>
              새로고침
            </button>
          </div>
          {#if loadingDevices}
            <div class="authenticator-empty"><span class="mp-spinner"></span>연결된 장치를 찾는 중…</div>
          {:else if authenticators.length === 0}
            <div class="authenticator-empty">연결된 FIDO2 보안 키가 없습니다.</div>
          {:else}
            <div class="authenticator-list compact-authenticator-list" role="radiogroup" aria-label="추가할 FIDO2 보안 키">
              {#each authenticators as device (device.path)}
                <label class="authenticator-option" class:authenticator-option--selected={addDevicePath === device.path}>
                  <input type="radio" name="add-authenticator" value={device.path} checked={addDevicePath === device.path} onchange={() => chooseAddDevice(device)}/>
                  <span class="authenticator-icon"><Icon name="usb" size={18}/></span>
                  <span class="authenticator-copy">
                    <strong>{device.product || "FIDO2 보안 키"}</strong>
                    <span>{device.windowsHello ? "Windows Security에서 장치를 선택합니다" : device.manufacturer || "제조사 정보 없음"}</span>
                  </span>
                </label>
              {/each}
            </div>
          {/if}
          <label class="mp-field">
            <span class="mp-field__label">레이블</span>
            <input class="mp-input" bind:value={addDeviceLabel} maxlength="128" placeholder="예: 사무실 YubiKey"/>
          </label>
          <label class="mp-field">
            <span class="mp-field__label">보안 키 PIN <span class="optional">(선택)</span></span>
            <input class="mp-input" type="password" bind:value={addDevicePin} autocomplete="off" placeholder="플랫폼에서 직접 처리하면 비워 두세요"/>
          </label>
          <div class="confirmation-actions rotation-actions">
            <button class="mp-button mp-button--secondary" type="button" disabled={busy} onclick={closeDeviceManager}>닫기</button>
            <button class="mp-button mp-button--primary" type="submit" disabled={busy || loadingDevices || !addDevicePath || !addDeviceLabel.trim()}>
              <Icon name="plus" size={16}/>
              {busy ? "보안 키 기다리는 중…" : "장치 추가"}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
{/if}

{#if kekRotationOpen}
  <div class="confirmation-backdrop" role="presentation">
    <div
      class="mp-card rotation-dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="rotation-title"
    >
      <form
        class="rotation-form"
        onsubmit={(event) => {
          event.preventDefault();
          void rotateKEK();
        }}
      >
      <div class="rotation-heading">
        <div class="confirmation-icon"><Icon name="key" size={22}/></div>
        <div class="confirmation-copy">
          <h2 id="rotation-title">Root KEK 회전</h2>
          <p>활성 슬롯에 새 FIDO credential과 salt를 만들고 vault DEK를 다시 보호합니다.</p>
        </div>
      </div>

      <p class="rotation-warning">
        현재 슬롯만 교체됩니다. 다른 장치 슬롯은 계속 사용할 수 있습니다.
      </p>

      <fieldset class="authenticator-picker rotation-authenticator-picker">
        <div class="authenticator-picker-heading">
          <legend class="mp-field__label">FIDO2 보안 키</legend>
          <button class="mp-button mp-button--ghost mp-button--sm" type="button" disabled={loadingDevices || busy} onclick={refreshRotationAuthenticators}>
            <Icon name="refresh" size={15}/>
            새로고침
          </button>
        </div>
        {#if loadingDevices}
          <div class="authenticator-empty"><span class="mp-spinner"></span>연결된 장치를 찾는 중…</div>
        {:else if authenticators.length === 0}
          <div class="authenticator-empty">연결된 FIDO2 보안 키가 없습니다.</div>
        {:else}
          <div class="authenticator-list" role="radiogroup" aria-label="KEK 회전용 FIDO2 보안 키">
            {#each authenticators as device (device.path)}
              <label class="authenticator-option" class:authenticator-option--selected={rotationDevicePath === device.path}>
                <input type="radio" name="rotation-authenticator" value={device.path} bind:group={rotationDevicePath}/>
                <span class="authenticator-icon"><Icon name="usb" size={19}/></span>
                <span class="authenticator-copy">
                  <strong>{device.product || "FIDO2 보안 키"}</strong>
                  <span>{device.windowsHello ? "Windows Security에서 장치를 선택합니다" : device.manufacturer || "제조사 정보 없음"}</span>
                </span>
                {#if !device.windowsHello}
                  <span class="authenticator-id">{formatUSBID(device.vendorId, device.productId)}</span>
                {/if}
              </label>
            {/each}
          </div>
        {/if}
      </fieldset>

      <label class="mp-field">
        <span class="mp-field__label">보안 키 PIN <span class="optional">(선택)</span></span>
        <input class="mp-input" name="rotation-pin" type="password" bind:value={rotationPin} autocomplete="off" placeholder="플랫폼에서 직접 처리하면 비워 두세요"/>
      </label>

      <div class="confirmation-actions rotation-actions">
        <button class="mp-button mp-button--secondary" type="button" disabled={busy} onclick={closeKEKRotation}>취소</button>
        <button class="mp-button mp-button--primary" type="submit" disabled={busy || loadingDevices || !rotationDevicePath}>
          <Icon name="refresh" size={16}/>
          {busy ? "보안 키 기다리는 중…" : "KEK 회전"}
        </button>
      </div>
      </form>
    </div>
  </div>
{/if}

{#if dekRotationOpen}
  <div class="confirmation-backdrop" role="presentation">
    <div
      class="mp-card rotation-dialog dek-rotation-dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="dek-rotation-title"
      aria-describedby="dek-rotation-description"
    >
      <div class="rotation-form">
        <div class="rotation-heading">
          <div class="confirmation-icon"><Icon name="refresh" size={22}/></div>
          <div class="confirmation-copy">
            <h2 id="dek-rotation-title">Vault DEK 회전</h2>
            <p id="dek-rotation-description">새 랜덤 DEK로 모든 저장 항목을 다시 암호화합니다. FIDO2 작업은 발생하지 않습니다.</p>
          </div>
        </div>

        {#if dekProgress.phase === "ready"}
          <p class="rotation-warning">
            새 데이터베이스가 완성될 때까지 기존 DB를 유지합니다. 완료되면 현재 사용 중인 슬롯만 남고 다른 장치 슬롯은 모두 폐기됩니다. 중단 시 다음 실행에서 자동 복구합니다.
          </p>
        {:else}
          <div class="dek-progress" class:dek-progress--failed={dekProgress.phase === "failed"}>
            <div class="dek-progress-heading">
              <strong>{dekProgress.phase === "failed" ? "회전을 완료하지 못했습니다" : dekProgress.message}</strong>
              <span>{dekProgress.percent}%</span>
            </div>
            <progress max="100" value={dekProgress.percent}>{dekProgress.percent}%</progress>
            <span class="dek-progress-count">
              {dekProgress.phase === "switching"
                ? "안전하게 DB를 교체하는 중입니다. 앱을 종료하지 마세요."
                : `${dekProgress.completed} / ${dekProgress.total}개 처리`}
            </span>
          </div>
        {/if}

        <div class="confirmation-actions rotation-actions">
          <button class="mp-button mp-button--secondary" type="button" disabled={dekRotationRunning} onclick={closeDEKRotation}>닫기</button>
          <button class="mp-button mp-button--primary" type="button" disabled={busy || dekRotationRunning} onclick={rotateDEK}>
            {#if dekRotationRunning}<span class="mp-spinner"></span>{:else}<Icon name="refresh" size={16}/>{/if}
            {dekRotationRunning ? "DEK 회전 중…" : dekProgress.phase === "failed" ? "다시 시도" : "DEK 회전 시작"}
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}

{#if pendingConfirmation}
  <div class="confirmation-backdrop" role="presentation">
    <div
      class="mp-card confirmation-dialog"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="confirmation-title"
      aria-describedby="confirmation-message"
    >
      <div class="confirmation-icon" class:confirmation-icon--danger={pendingConfirmation.destructive}>
        <Icon name={pendingConfirmation.destructive ? "trash" : "alert"} size={22}/>
      </div>
      <div class="confirmation-copy">
        <h2 id="confirmation-title">{pendingConfirmation.title}</h2>
        <p id="confirmation-message">{pendingConfirmation.message}</p>
      </div>
      <div class="confirmation-actions">
        <button class="mp-button mp-button--secondary" disabled={busy} onclick={closeConfirmation}>취소</button>
        <button
          class="mp-button"
          class:mp-button--danger={pendingConfirmation.destructive}
          class:mp-button--primary={!pendingConfirmation.destructive}
          disabled={busy}
          onclick={acceptConfirmation}
        >{pendingConfirmation.confirmLabel}</button>
      </div>
    </div>
  </div>
{/if}

<div class="mp-toast-region mp-toast-region--top-right" role="region" aria-label="알림" aria-live="polite">
  {#each toasts as toast (toast.id)}
    <div class="mp-toast mp-toast--{toast.tone}" role="status">
      <span class="mp-toast__icon">
        <Icon name={toast.tone === "success" ? "check" : toast.tone === "danger" ? "alert" : "info"} size={14}/>
      </span>
      <span class="mp-toast__body">
        <strong class="mp-toast__title">{toast.title}</strong>
        <span class="mp-toast__message">{toast.message}</span>
      </span>
    </div>
  {/each}
</div>
