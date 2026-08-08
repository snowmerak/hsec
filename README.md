# hsec

`hsec` is a minimal personal key-value vault built with Wails 3 and Svelte.
It derives encryption keys from a FIDO2 authenticator with
[`github.com/snowmerak/hmacsecret`](https://github.com/snowmerak/hmacsecret),
keeps the active data-encryption key in a
[`memguard`](https://github.com/awnumar/memguard) enclave, and uses
[`merak-protocol-design-system`](https://github.com/snowmerak/merakcss) for the
interface.

## Storage model

- `registry.sqlite` stays in the operating system's per-user application-data
  directory. It contains recently opened vault paths, access times, and a
  non-secret preferred-authenticator hint. It never stores a PIN or encryption
  key.
- Each user-selected vault folder contains its own `keys.sqlite` and
  `vault.sqlite`. The folder can be inside a locally synchronized directory
  such as Google Drive or iCloud Drive.
- `keys.sqlite` stores the public root KEK reference and a random vault DEK
  wrapped with that KEK. The vault DEK does not have its own FIDO credential.
- `vault.sqlite` stores the human-readable alias as its exact primary key and an
  XChaCha20-Poly1305 encrypted, versioned field document. Field names and values
  are encrypted together as one atomic payload.
- Initializing a vault performs exactly one FIDO credential creation and one
  HMAC-secret derivation. Unlocking performs one derivation. The active root KEK
  and vault DEK remain sealed in `memguard.Enclave` values until the vault is
  locked, allowing DEK rotation without another FIDO operation.
- KEK rotation creates and derives one replacement root credential, then
  rewraps both the metadata-store DEK and vault DEK without rewriting encrypted
  values. Vaults from the older two-credential format migrate their vault DEK
  on the first successful unlock.
- DEK rotation generates a new random key and re-encrypts every entry into a
  shadow database while the original remains untouched. A small journal in
  `keys.sqlite` makes the final file swap recoverable if the process or machine
  stops at any point.
- FIDO operations are serialized. If a create or derive operation takes longer
  than one second, the UI shows a persistent security-key touch prompt until the
  operation finishes.

An existing vault created by an older hsec build directly inside the application
data directory is registered in place on startup. Its database files are not
moved.

Legacy entries whose decrypted value is a single string are exposed as a
`메모` field and are rewritten in the document format on the next save.

On macOS and Linux, hsec lists connected FIDO2 authenticators and requires an
explicit choice when more than one is connected. The last successfully used
device is offered as a convenience hint the next time that vault is opened.
Windows continues through the Windows WebAuthn broker, where Windows Security
handles authenticator selection.

## Development

Requirements:

- Go 1.26.5
- Node.js and npm
- Wails 3 CLI
- `libfido2` and CGO on macOS/Linux, or Windows WebAuthn on Windows

```sh
npm install --prefix frontend
wails3 task dev
```

Build and verify:

```sh
go test ./...
go test -race ./...
go vet ./...
npm run --prefix frontend check
npm run --prefix frontend build
wails3 task build
```

The PIN field is optional: leave it blank when the operating system or
authenticator handles verification through its own UI.
