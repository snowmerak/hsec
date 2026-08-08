<script lang="ts">
  import {onMount} from "svelte";
  import {Dialogs, Events} from "@wailsio/runtime";
  import Icon from "./lib/Icon.svelte";
  import {
    isPreview,
    vault,
    type AuthenticatorInfo,
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
    };
  });

  async function loadStatus() {
    try {
      await refreshVaultReferences();
      status = await vault.Status();
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
        ? await vault.Unlock(selectedDevicePath, pin)
        : await vault.Initialize(selectedDevicePath, pin);
      pin = "";
      await refreshEntries();
      showToast("success", wasInitialized ? "vault가 열렸습니다" : "vault가 준비됐습니다", "보안 키로 암호화 키를 안전하게 유도했습니다.");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
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
      showToast("success", "KEK를 회전했습니다", "새 credential로 metadata DEK를 다시 보호했습니다.");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
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
  if (event.key === "Escape" && kekRotationOpen) {
    event.preventDefault();
    closeKEKRotation();
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
      <button class="mp-button mp-button--primary unlock-action" type="submit" disabled={busy || loadingDevices || authenticators.length === 0}>
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
          <p>새 FIDO credential과 salt를 만들고 metadata DEK를 다시 보호합니다.</p>
        </div>
      </div>

      <p class="rotation-warning">
        현재 vault DEK credential도 사용할 수 있는 보안 키를 선택해야 합니다. 다른 물리 키로의 이전은 DEK 회전 단계에서 지원합니다.
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
