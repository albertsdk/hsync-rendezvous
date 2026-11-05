# Getting Started — Windows installer

The installer is **per-machine** (administrator rights). It installs the daemon
and registers it as the Windows service **`hsync-rendezvous`** through
[WinSW](https://github.com/winsw/winsw), starting it automatically at boot.

## Prerequisites

- <img src="assets/os/windows.svg" alt="Windows" width="16" height="16"> Windows 10/11 or Windows Server (x64)
- Administrator rights
- A port reachable from the Internet (443 by default) over UDP and/or TCP — QUIC uses UDP, TLS/TCP uses TCP

## Install

Download the latest installer:

[Download hsync-rendezvous-windows-amd64-setup.exe](https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/hsync-rendezvous-windows-amd64-setup.exe)

Run it (the wizard prompts for elevation). The service is installed and started
automatically. The link always points to the **latest stable** release; to pin a
version, use the [Releases page](https://github.com/albertsdk/hsync-rendezvous/releases).

## Manage the service

Run PowerShell **as administrator**:

```powershell
Get-Service hsync-rendezvous
Start-Service hsync-rendezvous
Stop-Service hsync-rendezvous
Restart-Service hsync-rendezvous
```

- The TLS identity and the service logs are persisted under
  `C:\ProgramData\hsync-rendezvous` (logs in the `logs` subdirectory).
- The service definition is `hsync-rendezvous-service.xml` next to
  `hsync-rendezvous-service.exe` in the install directory.
- Protected buckets / private node: the installer creates
  `C:\ProgramData\hsync-rendezvous\group-keys` **empty** (open mode) and grants
  administrators write access / `LocalService` read access. Provision one
  `bucket=<hex-group-key>` line per protected bucket there and restart the
  service. For example:

  ```text
  shared=378767051d3c551e615922cbffb543563a93bbf39d615a2c46389c2f6b246068
  home=63379453eeb327abf615e2e89aa3921fb4c20edf11a12a260058ed299dc153cb
  ```

  (Mint a key per bucket with `openssl rand -hex 32`; comments and blank lines
  are ignored. The full format is in
  [usage.md → Group keys](usage.md#group-keys---keys-fd----keys-file).) For
  devices that use the GUI client's shared password instead, derive the key from
  that password with `hsync derive-group-key` and store its 64-hex output as the
  `bucket=<key>` line — the Desktop field always treats what a user types as a
  shared password, so a randomly minted key can never match it. The installed
  service already passes `--keys-file` for that file; for
  a fully private node uncomment the `HSYNC_RENDEZVOUS_PRIVATE` environment block
  in `hsync-rendezvous-service.xml` and restart (the one-switch equivalent of
  declaring `--protected-bucket` for every bucket in the keys file — see
  [Usage](../docs/usage.md#private-node-authenticated-rendezvous)). The node reads the file once at
  startup and never writes it.
- Read the fingerprint clients pin with
  `hsync-rendezvous identity show --identity C:\ProgramData\hsync-rendezvous\identity.pem`.
- To serve a **second** inbound port (for clients whose network blocks 443 on
  one transport), add `--listen-ports 443,53` to the service `<arguments>` in the XML above and
  open the extra port — see `--listen-ports` in
  [Usage](../docs/usage.md#run-options).

## Update and remove

Run the newer installer to upgrade. Removing HSYNC Rendezvous from
**Settings → Apps** stops and unregisters the service (the data under
`C:\ProgramData\hsync-rendezvous` is left in place).

## Next

- Full operation guide and group keys: see the repository `docs/usage.md`.
