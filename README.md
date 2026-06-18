# Secure Boot CA 2023 — AD Monitoring Toolchain

**Documentation v4.0**

A three-component toolchain for monitoring the Windows Secure Boot CA 2023 certificate update status across Active Directory-joined devices. No Intune, no Microsoft Graph API, no agent — data is collected via a GPO-deployed PowerShell script and visualised in a self-contained browser dashboard.

---

## Table of Contents

- [What is this toolchain?](#what-is-this-toolchain)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Network share setup](#network-share-setup)
- [Collector script](#collector-script)
  - [Configuration](#configuration)
  - [Output fields](#output-fields)
- [GPO scheduled task](#gpo-scheduled-task)
- [Aggregator script](#aggregator-script)
  - [Aggregator configuration](#aggregator-configuration)
  - [Output files](#output-files)
- [Dashboard — Loading data](#dashboard--loading-data)
- [Dashboard — Summary panels](#dashboard--summary-panels)
- [Dashboard — Filters & sorting](#dashboard--filters--sorting)
- [Dashboard — Table columns](#dashboard--table-columns)
- [Dashboard — Row detail](#dashboard--row-detail)
- [Dashboard — Export functions](#dashboard--export-functions)
- [Reference — BIOS compliance check](#reference--bios-compliance-check)
  - [Model matching](#model-matching)
  - [Version comparison](#version-comparison)
- [Reference — Status tokens](#reference--status-tokens)
- [Reference — Confidence Level values](#reference--confidence-level-values)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)

---

## What is this toolchain?

The **Windows Secure Boot CA 2023** update replaces ageing Secure Boot certificates on Windows devices. Microsoft is rolling out the update in phases from 2024 onwards; devices must meet BIOS version prerequisites before the certificate update can be applied.

This toolchain is designed for environments managed via **Active Directory and Group Policy** without Intune. It gives administrators the same level of status visibility as the native Intune Secure Boot Status report — covering CA 2023 rollout progress, registry state, event log diagnostics, and vendor BIOS readiness.

| | |
|---|---|
| Components | 3 |
| Dell models in DB | ~300 |
| HP models in DB | ~250 |
| Status tokens | 20+ |

> **Note:** All data is processed locally. The dashboard works entirely offline once the HTML file is opened — no data is transmitted to any server.

---

## Architecture

The toolchain consists of three components that run independently:

**1. Collector — `Get-SecureBootCA2023StatusFull_v4.0.ps1`**

Deployed via GPO Scheduled Task to every domain-joined Windows device. Runs as SYSTEM and writes a per-device JSON file to a central network share. Collects CA 2023 registry state, event log events, OS version, hardware and BIOS information.

**2. Aggregator — `Merge-SecureBootCA2023Status_v4.0.ps1`**

Runs nightly via Task Scheduler on a management server with read access to the share. Reads all per-device JSON files, derives status groupings, and produces a single combined JSON and a flat CSV file.

**3. Dashboard — `SecureBoot_CA2023_Dashboard_v4.4.html`**

A self-contained HTML file opened locally in a browser. The combined JSON is imported via drag-and-drop or file picker. The dashboard performs the BIOS compliance table lookup live at import time — no compliance data is baked into the JSON files.

---

## Requirements

| Component | Requirement |
|---|---|
| Collector devices | Windows 10 1809 or later, domain-joined, PowerShell 5.1+ |
| Network share | Write-only access for Domain Computers; read access for the aggregator service account |
| Aggregator host | Any Windows server or management PC with PowerShell 5.1+ and read access to the share |
| Dashboard | Modern browser (Chrome, Edge, Firefox, Safari) — no installation, no backend |

> **Warning:** The CA 2023 update and the associated registry keys (`UEFICA2023Status`, `ConfidenceLevel`, `BucketHash`) require the November 2025 or later Windows cumulative update. Devices that have not received this update will show `NO_EVENTS` or `UNKNOWN` status.

---

## Network share setup

Create a dedicated share accessible by all domain-joined devices:

| Principal | Share permission | NTFS permission |
|---|---|---|
| Domain Computers | Change | Create Files / Write Data only — no List or Read |
| Domain Admins | Full Control | Full Control |
| Service account (aggregator) | Read | Read & Execute, List folder contents |

Denying **List folder contents** to Domain Computers prevents devices from enumerating or reading each other's JSON files.

A `Combined` subfolder within the same share can be used as the aggregator output location.

---

## Collector script

The collector is a PowerShell 5.1 script that runs on each device and produces a JSON file containing the device's current CA 2023 status. It operates in three modes set by the `$OutputMode` variable at the top of the script.

### Configuration

| Variable | Default | Description |
|---|---|---|
| `$OutputMode` | `Collector` | `Verbose` for human-readable output (manual use), `CI` for a single status token (ConfigMgr CI), `Collector` for JSON output to the share (GPO deployment) |
| `$CollectorShare` | *(empty)* | UNC path to the network share, e.g. `\\server\SecureBootCA2023$`. When empty in Collector mode, the JSON is written to stdout. |
| `$MaxEventDetail` | `10` | Maximum number of events shown in Verbose mode output. |

### Output fields

| Field | Source | Description |
|---|---|---|
| `ComputerName` | Environment | Device hostname |
| `CollectedAt` | System clock | UTC timestamp of collection (ISO 8601) |
| `Status` | Derived | Primary status token — see [Status tokens](#reference--status-tokens) |
| `RegDerivedStatus` | Registry | Status derived from `UEFICA2023Status` and `UEFICA2023Error` |
| `StatusDetail` | Event log | Human-readable event log summary |
| `RegStatus` | Registry | Raw `UEFICA2023Status` value: `Updated` / `InProgress` / `NotStarted` |
| `RegError` | Registry | `UEFICA2023Error` error code (0 = no error) |
| `RegErrorEvent` | Registry | Event ID associated with the last registry error |
| `ConfidenceLevel` | Registry / Event log | Microsoft's confidence classification for this device |
| `BucketHash` | Registry / Event log | Telemetry bucket identifier |
| `SkipReason` | Event log | OEM skip reason code from Event 1802 (e.g. `KI_7`) |
| `OSCaption` | WMI | Operating system name |
| `OSBuildNumber` | WMI | Windows build number |
| `SystemManufacturer` | WMI | Device manufacturer from `Win32_ComputerSystem.Manufacturer` |
| `SystemModel` | WMI | Device model from `Win32_ComputerSystem.Model` |
| `BIOSVersion` | WMI | Raw BIOS version string from `Win32_BIOS.SMBIOSBIOSVersion` |
| `BIOSVersionParsed` | WMI / derived | Extracted numeric version, e.g. `02.22` |
| `BIOSReleaseDate` | WMI | BIOS release date in `yyyy-MM-dd` format |
| `IsVirtualMachine` | WMI / heuristic | `true` if detected as a virtual machine |
| `SecureBootStatus` | Registry | `Enabled` / `Disabled` / `LegacyBIOS` |
| `HpSbkpfv3Present` | WMI (HP only) | Whether the HP BIOS contains the `SBKPFV3` key (HP-specific CA 2023 BIOS marker) |
| `EventCount` | Event log | Total number of CA 2023 events in the System log |
| `LastEventId` | Event log | ID of the most recent CA 2023 event |
| `LastEventTime` | Event log | UTC timestamp of the most recent event |

> **Note:** BIOS compliance fields (`BiosReadyStatus`, `BiosUpdateRequired`, `MinBiosVersion`, `MatchedModel`) are **not stored in the JSON**. The dashboard computes these live from the embedded HP and Dell tables at import time. To update the compatibility tables, edit the dashboard HTML — no re-collection needed.

---

## GPO scheduled task

The repository includes a ready-to-use GPO XML file (`SecureBoot-CA2023-StatusCollector_GPO.xml`) that can be imported under **Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks** (type: *Scheduled Task (At least Windows 7)*).

**Steps:**

1. **Deploy the script** — Copy `Get-SecureBootCA2023StatusFull_v4.0.ps1` to a SYSVOL scripts folder or any UNC path readable by all domain computers.

2. **Update the placeholder** — Open the GPO XML and replace the `*** CHANGE ME ***` placeholder with the full path to the script:
   ```
   powershell.exe -NonInteractive -ExecutionPolicy Bypass -File "\\domain\NETLOGON\SecureBoot\Get-SecureBootCA2023StatusFull_v3_0.ps1"
   ```

3. **Import the XML into the GPO** — In the Group Policy Management Console, right-click the Scheduled Tasks node and paste or import the XML.

4. **Link and configure the GPO** — Link to the OUs containing target computers. The task runs as `SYSTEM`, requires no credentials, and triggers daily plus on system startup. Set `$CollectorShare` in the script before deployment.

---

## Aggregator script

The aggregator reads all per-device JSON files from the share and produces a combined dataset for the dashboard. It derives additional grouping fields (`StatusGroup`, `ConfidenceGroup`, `Stale`) that the dashboard uses for filtering and statistics.

### Aggregator configuration

| Variable | Default | Description |
|---|---|---|
| `$SourceShare` | *(placeholder)* | UNC path to the network share containing the per-device JSON files |
| `$OutputFolder` | *(placeholder)* | Path where the combined JSON and CSV are written |
| `$StaleDays` | `7` | Devices whose JSON is older than this many days receive `Stale = true` |

### Output files

| File | Description |
|---|---|
| `SecureBootCA2023_v4_Combined.json` | Full dataset for dashboard import. Includes a metadata header (`_MergedBy`, `_GeneratedAt`, `_DeviceCount`, `_StaleCount`, `_ParseErrors`) and a `Devices` array. |
| `SecureBootCA2023_v4_Combined.csv` | Flat CSV for Excel or cross-reference. UTF-8, all device fields as columns. BIOS compliance fields are not included. |

> **Note:** The aggregator does not compute `BiosReadyStatus`. Use the dashboard for BIOS compliance reporting.

---

## Dashboard — Loading data

Open `SecureBoot_CA2023_Dashboard_v4.4.html` locally in a browser. No web server is needed.

1. **Obtain the combined JSON** — Run the aggregator to produce `SecureBootCA2023_v4_Combined.json`, or use individual device JSON files for smaller batches.

2. **Import the file** — Drag-and-drop the JSON onto the dashboard, or click the upload area and use the file picker. Both combined aggregator JSON and individual device JSON files are supported; multiple files can be loaded at once.

3. **BIOS compliance is computed automatically** — The dashboard looks up each device's model in the HP and Dell compatibility tables immediately on import. No additional steps are required.

---

## Dashboard — Summary panels

| Panel | Content |
|---|---|
| **Summary cards** | Total, Complete, Action Required, In Progress, Unknown, Stale — each card filters the table when clicked |
| **Confidence Level** | Bar chart of devices by Confidence Level value — each row filters the table |
| **BIOS Compliance — HP & Dell** | HP and Dell device counts with OK / Update Required / End of Life breakdown per vendor. "Show BIOS action needed" link filters the table. |
| **Data source** | Loaded file name, aggregator generation timestamp, device count, stale count, parse errors |

---

## Dashboard — Filters & sorting

| Filter | Description |
|---|---|
| Computer name search | Case-insensitive substring match on device hostname |
| Status | Dropdown with all status tokens present in the dataset |
| Confidence Level | Dropdown with all Confidence Level values present in the dataset |
| BIOS update needed | Checkbox — shows only devices where `BiosUpdateRequired = true` |
| Stale only | Checkbox — shows only devices older than the stale threshold (default: 7 days) |

All table columns are sortable by clicking the column header. **Clear** resets all filters.

---

## Dashboard — Table columns

| Column | Description |
|---|---|
| **Computer Name** | Device hostname. A `stale` pill appears if the JSON exceeds the stale threshold. |
| **Collected** | Date the collector last ran on this device (UTC). |
| **Status** | Colour-coded CA 2023 status badge — see [Status tokens](#reference--status-tokens). |
| **Confidence Level** | Microsoft's confidence classification badge. |
| **Model** | Device model from `Win32_ComputerSystem.Model`. Empty for v2.1-collected devices. |
| **BIOS Ready** | Live BIOS compliance lookup result — see [BIOS compliance check](#reference--bios-compliance-check). |
| **Last Event** | ID of the most recent CA 2023 event (TPM-WMI provider). |
| **Reg Status** | Raw `UEFICA2023Status` registry value. |

---

## Dashboard — Row detail

Click the ▶ expand button on any row to open the full device detail, divided into five groups:

| Group | Fields |
|---|---|
| **Hardware & OS** | OS name and build, system manufacturer and model, VM flag, Secure Boot state |
| **Status** | Status token, status group, registry-derived status, collection timestamp, stale flag, full status detail text |
| **Registry** | UEFICA2023Status, UEFICA2023Error (colour-coded), error event ID, Capable reference, event count, last event ID and timestamp |
| **Confidence & Bucket** | Confidence Level, source, BucketHash, DeviceAttributes, UpdateType, SkipReason |
| **BIOS Details** | BIOS manufacturer, raw/parsed version, release date, BIOS Ready badge, minimum required version, matched table key, match method (exact / subset / fuzzy %), BIOS list source, HP SBKPFV3 flag |

> The **Matched table key** and **Match method** fields show which HP/Dell table entry was used and how it was found, making fuzzy matches transparent and auditable.

---

## Dashboard — Export functions

### CSV export

Exports the currently filtered view as a UTF-8 CSV containing all device fields plus BIOS compliance fields computed by the dashboard:

- Identity & status: `ComputerName`, `CollectedAt`, `Stale`, `Status`, `StatusGroup`, `StatusDetail`, `RegDerivedStatus`
- Registry: `RegStatus`, `RegError`, `RegErrorEvent`, `RegCapable`
- Confidence: `ConfidenceLevel`, `ConfidenceLevelSource`, `ConfidenceGroup`, `BucketHash`, `DeviceAttributes`, `UpdateType`, `SkipReason`
- Events: `EventCount`, `LastEventId`, `LastEventTime`
- OS & hardware: `OSCaption`, `OSBuildNumber`, `SystemManufacturer`, `SystemModel`
- BIOS: `BIOSManufacturer`, `BIOSVersion`, `BIOSVersionParsed`, `BIOSReleaseDate`
- Platform: `IsVirtualMachine`, `SecureBootStatus`
- BIOS compliance (dashboard): `BiosReadyStatus`, `BiosUpdateRequired`, `MinBiosVersion`, `BiosListSource`
- HP legacy: `CspVendor`, `CspVersion`, `IsHpDevice`, `HpSbkpfv3Present`

### HTML report

Generates a fully self-contained HTML file with the summary cards snapshot and a sortable device table for the currently filtered view. The report can be shared and opened without the main dashboard.

---

## Reference — BIOS compliance check

The dashboard performs a live lookup of each device's model against vendor-published compatibility tables at import time. No BIOS compliance data is stored in the JSON files.

| Value | Meaning |
|---|---|
| **OK** | Installed BIOS meets or exceeds the minimum required version |
| **Update Required** | BIOS is below the minimum version — update before the CA 2023 update can proceed |
| **End of Life** | No BIOS update available for this model; CA 2023 update cannot be applied (HP only) |
| **Not in List** | Device model not found in the HP or Dell compatibility table |
| **N/A** | Device is not HP or Dell, or is a virtual machine |

**Sources:**
- HP: [HP support document ISH_13070353](https://support.hp.com/us-en/document/ish_13070353-13070429-16) (April 2026)
- Dell: [Dell KB 000347876](https://www.dell.com/support/kbdoc/en-us/000347876) (April 2026)

> To update the tables, edit the `DELL_BIOS_TABLE` and `HP_BIOS_TABLE` JavaScript constants in the dashboard HTML. All historical JSON files are instantly re-evaluated on next import.

### Model matching

Device model strings from WMI can differ from table keys due to marketing language, punctuation, and OEM configuration. The dashboard uses a three-stage matching pipeline:

**Normalisation** — Both device model and table key are lowercased, non-alphanumeric characters replaced with spaces, and consecutive spaces collapsed.

**Stage 1 — Exact match** — Normalised device model compared directly against every normalised table key.

**Stage 2 — Token subset** — Every word token from the table key must be present in the device model's token set, regardless of additional words (e.g. "Inch", "Notebook PC", "2-in-1"). The longest matching key wins. A **critical token guard** rejects candidates where a numeric or generation token (e.g. `G5`, `840`) in the table key is absent from the device tokens — preventing cross-generation false matches such as G3 matching G5.

**Stage 3 — Jaccard similarity** — Jaccard word-token similarity computed against all remaining candidates (after the critical token guard). Best-scoring candidate above 60% is used. Match stage and score are recorded in the row detail.

### Version comparison

BIOS versions are compared numerically, part by part (split on `.`). Each part is cast as an integer, handling leading zeros (`01.10.00` → `[1, 10, 0]`) and differing part counts (`02.67` vs `02.20.00`). HP BIOS version strings may carry a model prefix (`P01 Ver. 02.22`); the extractor picks the first `digit.digit` sequence.

---

## Reference — Status tokens

| Token | Group | Meaning |
|---|---|---|
| `COMPLETE` | Compliant | UEFICA2023Status = Updated |
| `COMPLETE_REG` | Compliant | No events but Capable ≥ 2 (cert + boot mgr) |
| `IN_PROGRESS` | In Progress | InProgress with no blocking error |
| `PARTIAL_REG` | In Progress | No events but Capable = 1 (cert in DB only) |
| `PENDING` | In Progress | Event log indicates a pending step |
| `PENDING_REBOOT` | In Progress | Event 1800: reboot required |
| `PENDING_FIRMWARE` | In Progress | Event 1801: certs in OS not yet written to firmware |
| `BLOCKED` | Action Required | Generic blocked state |
| `BLOCKED_BITLOCKER` | Action Required | Event 1032: BitLocker recovery risk — suspend for 2 reboots first |
| `BLOCKED_BOOTLOADER` | Action Required | Event 1033: vulnerable/revoked boot loader on EFI partition |
| `BLOCKED_FIRMWARE_ISSUE` | Action Required | Event 1802: known OEM firmware issue — see SkipReason and KB 5039942 |
| `BLOCKED_NO_KEK` | Action Required | Event 1803: no PK-signed KEK found |
| `ERROR` | Action Required | Unclassified error |
| `ERROR_FIRMWARE` | Action Required | Event 1795: firmware error during Secure Boot update |
| `ERROR_UNEXPECTED` | Action Required | Event 1796: unexpected error — Windows will retry |
| `ERROR_DB_MISSING` | Action Required | Event 1797: UEFI CA 2023 not in DB; DBX update deferred |
| `ERROR_BOOTMGR_UNSIGNED` | Action Required | Event 1798: boot manager not CA-2023-signed; DBX deferred |
| `NOT_STARTED` | Unknown | UEFICA2023Status = NotStarted |
| `NO_EVENTS` | Unknown | No CA 2023 events found and registry key absent |
| `LOG_ACCESS_ERR` | Unknown | Cannot read the System event log |
| `UNKNOWN` | Unknown | Status cannot be determined |

---

## Reference — Confidence Level values

Populated from the `ConfidenceLevel` registry value (requires November 2025 CU or later) or from event log field extraction. Values as documented in Microsoft KB 5016061 / KB 5068202.

| Value | Meaning |
|---|---|
| **High Confidence** | Microsoft has high confidence the device will accept the update. Automatic deployment recommended. |
| **Under Observation** | Device is in a monitoring group. Cautious deployment. |
| **No Data Observed** | Insufficient telemetry for this device or model. |
| **Temporarily Paused** | Deployment paused due to a known issue (see SkipReason / Event 1802). |
| **Not Supported** | Device or configuration is not supported for this update. |

---

## Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| Status shows `NO_EVENTS` / `UNKNOWN` for all devices | Devices have not received the November 2025 CU | Install November 2025 or later CU; registry keys and events only appear after this update |
| `Reg Derived` or `UEFICA2023Error` showed `[object Object]` | PowerShell 5.1 `ConvertTo-Json` serialised a null-like registry value as `{}` | Dashboard v3.0 automatically treats `{}` as null and displays `—`. The Status token is still computed correctly from the event log. |
| BIOS Ready shows `Not in List` for a known HP/Dell device | Model string from WMI does not match any table entry at ≥60% similarity | Check **Matched table key** and **Match method** in the row detail. Add the model string as an additional key in the dashboard HTML if needed. |
| Device shows a wrong BIOS table match | Jaccard fuzzy match selected a similar but incorrect entry | The critical token guard prevents cross-generation matches (G3 ≠ G5). Add an exact key for the device model in the dashboard HTML. |
| JSON parse error on import | Malformed or empty JSON file | Check for parse errors in the aggregator summary output. |
| All devices show as stale | Collector GPO not running or share path incorrect | Verify GPO application (`gpresult /r`). Check that `$CollectorShare` matches the actual share UNC path. |
| Model column is empty for all devices | JSON files were collected with the v2.1 collector | Re-collect with the v3.0 collector. Existing v2.1 files load correctly but BIOS compliance data requires the hardware fields. |
| Share write fails for devices | Domain Computers lack Create Files permission | Verify NTFS permissions: Domain Computers need *Create Files / Write Data*. Read and List should be denied. |

---

## Changelog

### v3.0 — June 2026

- Collector: added OS fields (`OSCaption`, `OSBuildNumber`), hardware fields (`SystemManufacturer`, `SystemModel`), BIOS fields (`BIOSVersion`, `BIOSVersionParsed`, `BIOSReleaseDate`), platform fields (`IsVirtualMachine`, `SecureBootStatus`)
- BIOS compliance tables (HP ~250 entries, Dell ~300 entries) moved from collector script into dashboard HTML — update tables by editing the HTML, no re-collection needed
- Dashboard: BIOS compliance computed live at import via 3-stage model matching (exact → token-subset → Jaccard ≥60%) with critical token guard to prevent cross-generation false matches
- Dashboard: new **Model** column and **BIOS Ready** column (replaces HP SBKPFV3 column)
- Dashboard: **BIOS Compliance — HP & Dell** panel with per-vendor breakdown (replaces HP-only panel)
- Dashboard: **BIOS update needed** filter (replaces HP only filter)
- Dashboard: Hardware & OS and BIOS Details sections added to row detail
- Dashboard: `[object Object]` display bug fixed for `RegDerivedStatus` and `RegError` serialised as `{}` by PowerShell 5.1
- Aggregator: all v3.0 hardware fields added to combined JSON and CSV; v2.1 field-mapping bugs fixed (`BucketId`→`BucketHash`, missing `RegDerivedStatus`/`RegErrorEvent`/`StatusDetail`)

### v2.1 — May 2026

- Registry-primary status derivation: `UEFICA2023Status` and `UEFICA2023Error` as primary source; event log as fallback and detail
- HP SBKPFV3 check via `Win32_ComputerSystemProduct.Version`
- HP BIOS minimum version table added to collector
- Aggregator: combined JSON with metadata header and status groupings

### v2.0 — April 2026

- Full CA 2023 event log analysis (20 event IDs, TPM-WMI provider)
- ConfidenceLevel and BucketHash collection
- Dashboard with summary cards, confidence panel, filters, sortable table, expandable rows
- CSV and HTML report export
