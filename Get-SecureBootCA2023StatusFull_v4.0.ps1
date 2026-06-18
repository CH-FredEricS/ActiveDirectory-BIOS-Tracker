#Requires -Version 5.1
<#
.SYNOPSIS
    Get-SecureBootCA2023StatusFull_v3_0.ps1
    Collects Secure Boot CA 2023 update status AND full hardware context,
    with a unified BIOS compatibility check for HP and Dell devices.

.DESCRIPTION
    NEW IN v3.0
    -----------
    - OS information (Caption, Build Number)
    - Hardware context (System Manufacturer, Model)
    - BIOS information (Manufacturer, Version, Release Date)
    - Virtual machine detection
    - Secure Boot state (Enabled / Disabled / LegacyBIOS)
    - Raw BIOS info collected for table-based lookup in the dashboard
      (SystemManufacturer, SystemModel, BIOSVersion, BIOSVersionParsed)

    UNCHANGED FROM v2.0 / v2.1
    ---------------------------
    - Full registry-primary CA2023 status derivation
    - Event log detail (TPM-WMI events 1032-1808)
    - ConfidenceLevel / BucketHash from registry with event log fallback
    - All three output modes: Verbose | CI | Collector

.NOTES
    Registry path : HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
    Event source  : System log, Provider: Microsoft-Windows-TPM-WMI
    KB Reference  : https://support.microsoft.com/en-us/topic/37e47cf8-608b-4a87-8175-bdead630eb69
    KB updated    : 2026-06-02
    Min PowerShell: 5.1
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

[string] $OutputMode     = "Collector"   # Verbose | CI | Collector
[int]    $MaxEventDetail = 10            # Max events shown in Verbose mode
[string] $CollectorShare = '\\INFRANBX271\Test$'            # UNC share for Collector mode e.g. '\\server\SecureBootCA2023$'


# ============================================================================
#  HELPER FUNCTIONS  -  New in v3.0
# ============================================================================

function Extract-BiosVersion {
    <#
    .SYNOPSIS
        Extracts the numeric version portion from a raw BIOS version string.
        HP devices often prefix with a model code: "Q71 Ver. 01.10.00" -> "01.10.00"
        Dell and others typically return the version directly: "1.35.0"
    #>
    param([string]$VersionString)
    if ([string]::IsNullOrWhiteSpace($VersionString)) { return $null }
    # Match first occurrence of digits-dot-digits (one or more dot-separated groups)
    $m = [regex]::Match($VersionString, '(\d+(?:\.\d+)+)')
    if ($m.Success) { return $m.Value }
    return $null
}


function Get-SecureBootStateFromRegistry {
    <#
    .SYNOPSIS
        Returns the Secure Boot state by reading the registry directly.
        Avoids Confirm-SecureBootUEFI which is unavailable on some builds.
    .OUTPUTS  Enabled | Disabled | LegacyBIOS | Unknown
    #>
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    if (-not (Test-Path -LiteralPath $path)) { return 'LegacyBIOS' }
    try {
        $val = (Get-ItemProperty -LiteralPath $path -Name 'UEFISecureBootEnabled' `
                    -ErrorAction Stop).UEFISecureBootEnabled
        if ($val -eq 1) { return 'Enabled'  }
        if ($val -eq 0) { return 'Disabled' }
        return 'Unknown'
    }
    catch { return 'Unknown' }
}


function Get-IsVirtualMachine {
    <#
    .SYNOPSIS
        Heuristic VM detection via Win32_ComputerSystem manufacturer/model strings.
        VMs do not need physical firmware-level Secure Boot CA updates.
    #>
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $vmMarkers = 'Virtual','VMware','VirtualBox','KVM','QEMU','Xen','HVM',
                     'innotek','Parallels','Bochs','BHYVE'
        foreach ($m in $vmMarkers) {
            if ($cs.Manufacturer -like "*$m*" -or $cs.Model -like "*$m*") { return $true }
        }
    }
    catch {}
    return $false
}


# ============================================================================
#  HELPER FUNCTIONS  -  Retained from v2.1
# ============================================================================

function Get-RegValue {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Name
    )
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try   { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}


function Get-EventDescription {
    param([Parameter(Mandatory)][int] $Id)
    $map = @{
        1032 = @{ StatusClass = 'BLOCKED'; Description = 'BitLocker would enter recovery mode if update is applied. Suspend BitLocker for 2 reboots (Manage-bde -Protectors -Disable %systemdrive% -RebootCount 2) then reboot twice.' }
        1033 = @{ StatusClass = 'BLOCKED'; Description = 'Vulnerable or revoked boot loader detected on EFI partition. Contact OEM for an updated boot loader.' }
        1034 = @{ StatusClass = 'SUCCESS'; Description = 'DBX (revocation list) update applied to firmware successfully.' }
        1036 = @{ StatusClass = 'SUCCESS'; Description = 'DB (trusted signature database) update applied to firmware successfully.' }
        1037 = @{ StatusClass = 'SUCCESS'; Description = 'Windows Production PCA 2011 revocation added to DBX successfully.' }
        1042 = @{ StatusClass = 'SUCCESS'; Description = 'DBX Secure Version Number (SVN) rollback-protection update applied successfully.' }
        1043 = @{ StatusClass = 'SUCCESS'; Description = 'Microsoft Corporation KEK CA 2023 certificate applied to KEK variable successfully.' }
        1044 = @{ StatusClass = 'SUCCESS'; Description = 'Microsoft Option ROM CA 2023 certificate added to DB successfully.' }
        1045 = @{ StatusClass = 'SUCCESS'; Description = 'Microsoft UEFI CA 2023 certificate added to DB successfully. This is the primary certificate the update chain depends on.' }
        1795 = @{ StatusClass = 'ERROR';   Description = 'Firmware returned an error during Secure Boot variable update. Check event message for the error code. Contact device manufacturer.' }
        1796 = @{ StatusClass = 'ERROR';   Description = 'Unexpected error during Secure Boot update. Windows will retry automatically on next restart.' }
        1797 = @{ StatusClass = 'ERROR';   Description = 'UEFI CA 2023 not yet in DB. DBX revocation intentionally deferred. Waiting for DB update (Event 1045/1036) to complete first.' }
        1798 = @{ StatusClass = 'ERROR';   Description = 'Default boot manager not signed by UEFI CA 2023. DBX update deferred. Boot manager update must complete first.' }
        1799 = @{ StatusClass = 'SUCCESS'; Description = 'Boot manager signed with Windows UEFI CA 2023 installed successfully. DBX revocation can now proceed.' }
        1800 = @{ StatusClass = 'PENDING'; Description = 'Reboot required before this Secure Boot update can proceed.' }
        1801 = @{ StatusClass = 'PENDING'; Description = 'Certificates updated in Windows but not yet written to device firmware. See https://go.microsoft.com/fwlink/?linkid=2301018' }
        1802 = @{ StatusClass = 'BLOCKED'; Description = 'Update blocked by known OEM firmware/hardware issue. SkipReason field identifies the specific issue. See https://go.microsoft.com/fwlink/?linkid=2339472' }
        1803 = @{ StatusClass = 'BLOCKED'; Description = 'No PK-signed KEK found for this device. KEK update cannot proceed until OEM provides a signed KEK to Microsoft.' }
        1808 = @{ StatusClass = 'COMPLETE'; Description = 'FULLY UPDATED - All required CA 2023 certificates applied to firmware AND boot manager updated. No further action required.' }
    }
    if ($map.ContainsKey($Id)) { return $map[$Id] }
    return @{ StatusClass = 'UNKNOWN'; Description = "Event ID $Id is not listed in KB 5016061. Check for script updates." }
}


function Get-EventFields {
    param([Parameter(Mandatory)][string]$Message)
    $fields = [ordered]@{
        DeviceAttributes      = $null
        BucketId              = $null
        BucketConfidenceLevel = $null
        UpdateType            = $null
        SkipReason            = $null
    }
    if ($Message -match '(?m)^\s*DeviceAttributes\s*:\s*(.+)$')      { $fields.DeviceAttributes      = $Matches[1].Trim() }
    if ($Message -match '(?m)^\s*BucketId\s*:\s*(.+)$')              { $fields.BucketId              = $Matches[1].Trim() }
    if ($Message -match '(?m)^\s*BucketConfidenceLevel\s*:\s*(.+)$') { $fields.BucketConfidenceLevel = $Matches[1].Trim() }
    if ($Message -match '(?m)^\s*UpdateType\s*:\s*(.+)$')            { $fields.UpdateType            = $Matches[1].Trim() }
    if ($Message -match '(?m)^\s*SkipReason\s*:\s*(\S+)')            { $fields.SkipReason            = $Matches[1].Trim() }
    return $fields
}


# ============================================================================
#  SECTION 0  -  OS, HARDWARE AND BIOS INFORMATION  (new in v3.0)
# ============================================================================

# OS information
$osCaption = $null
$osBuild   = $null
try {
    $osObj     = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $osCaption = $osObj.Caption
    $osBuild   = $osObj.BuildNumber
}
catch { $osCaption = "CIM error: $($_.Exception.Message)" }

# System (hardware) information
$sysManufacturer = $null
$sysModel        = $null
try {
    $sysObj          = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $sysManufacturer = $sysObj.Manufacturer
    $sysModel        = $sysObj.Model
}
catch { $sysManufacturer = "CIM error: $($_.Exception.Message)" }

# BIOS information
$biosManufacturer  = $null
$biosVersion       = $null   # Raw SMBIOSBIOSVersion (may include model prefix on HP)
$biosVersionParsed = $null   # Extracted numeric version for display and comparison
$biosReleaseDate   = $null
try {
    $biosObj          = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $biosManufacturer = $biosObj.Manufacturer
    $biosVersion      = $biosObj.SMBIOSBIOSVersion
    $biosVersionParsed = Extract-BiosVersion -VersionString $biosVersion
    if ($biosObj.ReleaseDate) {
        $biosReleaseDate = $biosObj.ReleaseDate.ToString('yyyy-MM-dd')
    }
}
catch { $biosManufacturer = "CIM error: $($_.Exception.Message)" }

# Virtual machine detection
$isVirtualMachine = Get-IsVirtualMachine

# Secure Boot state
$secureBootStatus = Get-SecureBootStateFromRegistry


# ============================================================================
#  SECTION 1  -  CA2023 REGISTRY  (current-state snapshot, unchanged from v2.1)
# ============================================================================

$regBase      = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$regServicing = Join-Path $regBase 'Servicing'

$regStatus     = Get-RegValue -Path $regServicing -Name 'UEFICA2023Status'
$regError      = Get-RegValue -Path $regServicing -Name 'UEFICA2023Error'
$regCapable    = Get-RegValue -Path $regServicing -Name 'WindowsUEFICA2023Capable'
$regErrorEvent = Get-RegValue -Path $regServicing -Name 'UEFICA2023ErrorEvent'
$regConfidence = Get-RegValue -Path $regServicing -Name 'ConfidenceLevel'
$regBucketHash = Get-RegValue -Path $regServicing -Name 'BucketHash'

$capableDesc = if ($null -eq $regCapable) {
    '(not present)'
} else {
    switch ([int]$regCapable) {
        0       { '0 - CA 2023 certificate NOT present in DB' }
        1       { '1 - CA 2023 certificate present in DB' }
        2       { '2 - CA 2023 in DB AND boot manager is CA-2023-signed' }
        default { "$regCapable - Unrecognised value" }
    }
}

$regDerivedStatus = if ($null -eq $regStatus) { $null }
    elseif ($regStatus -eq 'Updated')    { 'COMPLETE' }
    elseif ($regStatus -eq 'NotStarted') { 'NOT_STARTED' }
    elseif ($regStatus -eq 'InProgress') {
        if ($null -ne $regError -and [int]$regError -ne 0) {
            if ($null -ne $regErrorEvent) {
                switch ([int]$regErrorEvent) {
                    1032 { 'BLOCKED_BITLOCKER' }     1033 { 'BLOCKED_BOOTLOADER' }
                    1795 { 'ERROR_FIRMWARE' }         1796 { 'ERROR_UNEXPECTED' }
                    1797 { 'ERROR_DB_MISSING' }       1798 { 'ERROR_BOOTMGR_UNSIGNED' }
                    1800 { 'PENDING_REBOOT' }         1801 { 'PENDING_FIRMWARE' }
                    1802 { 'BLOCKED_FIRMWARE_ISSUE' } 1803 { 'BLOCKED_NO_KEK' }
                    default { 'ERROR' }
                }
            } else { 'ERROR' }
        } else { 'IN_PROGRESS' }
    }
    else { 'UNKNOWN' }


# ============================================================================
#  SECTION 1b  -  HP SBKPFV3 CHECK  (retained from v2.1 as additional signal)
#  Reads Win32_ComputerSystemProduct.Version to detect the SBKPFV3 key.
#  This is an HP-specific check; it detects the SBKPFV3 key in the BIOS.
# ============================================================================

$cspVersion = $null
$cspVendor  = $null
$cspError   = $null
try {
    $cimProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
    $cspVersion = $cimProduct.Version
    $cspVendor  = $cimProduct.Vendor
}
catch { $cspError = $_.Exception.Message }

$isHpDevice       = (($null -ne $cspVendor)  -and ($cspVendor  -match '(?i)^HP$|Hewlett.Packard')) -or
                    (($null -ne $sysManufacturer) -and ($sysManufacturer -match '(?i)^HP$|Hewlett.Packard'))
$hpSbkpfv3Present = if ($isHpDevice) { [bool]($cspVersion -match 'SBKPFV3') } else { $null }

$hpBiosStatus = if (-not $isHpDevice) {
    'N/A (not an HP device)'
} elseif ($null -eq $cspVersion -or $cspError) {
    'UNKNOWN - Win32_ComputerSystemProduct.Version could not be read'
} elseif ($hpSbkpfv3Present) {
    'OK - SBKPFV3 present in Version string'
} else {
    'ACTION REQUIRED - SBKPFV3 absent; HP BIOS update needed'
}


# ============================================================================
#  SECTION 2  -  EVENT LOG  (unchanged from v2.1)
# ============================================================================

[int[]] $targetIds = @(
    1032, 1033, 1034, 1036, 1037, 1042, 1043, 1044, 1045,
    1795, 1796, 1797, 1798, 1799, 1800, 1801, 1802, 1803, 1808
)

$logError  = $null
$allEvents = @()

$xpathIdList = ($targetIds | ForEach-Object { "EventID=$_" }) -join ' or '
$xpathQuery  = "*[System[Provider[@Name='Microsoft-Windows-TPM-WMI'] and ($xpathIdList)]]"

try {
    $allEvents = @(
        Get-WinEvent -LogName 'System' -FilterXPath $xpathQuery -ErrorAction SilentlyContinue |
        Sort-Object -Property TimeCreated -Descending
    )
}
catch {
    $logError  = $_.Exception.Message
    $allEvents = @()
}

$latestById = @{}
foreach ($evt in $allEvents) {
    if (-not $latestById.ContainsKey($evt.Id)) { $latestById[$evt.Id] = $evt }
}

$evtStatus = 'NO_EVENTS - No Microsoft-Windows-TPM-WMI Secure Boot events found in System log.'

if ($logError) {
    $evtStatus = "LOG_ACCESS_ERROR - Cannot read System event log: $logError"
}
elseif ($latestById.ContainsKey(1808)) {
    $evtStatus = 'COMPLETE - Device fully updated. All CA 2023 certificates applied to firmware and boot manager updated (Event 1808).'
}
elseif ($latestById.ContainsKey(1802)) {
    $sr = ''; if ($latestById[1802].Message -match '(?i)SkipReason:\s*(\S+)') { $sr = " SkipReason: $($Matches[1])" }
    $evtStatus = "BLOCKED - Known OEM firmware/hardware issue (Event 1802).$sr See https://go.microsoft.com/fwlink/?linkid=2339472"
}
elseif ($latestById.ContainsKey(1803)) {
    $evtStatus = 'BLOCKED - No PK-signed KEK found for this device (Event 1803). Contact device manufacturer.'
}
elseif ($latestById.ContainsKey(1033)) {
    $bm = ''; if ($latestById[1033].Message -match '(?i)BootMgr:\s*(.+)') { $bm = " Affected: $($Matches[1].Trim())" }
    $evtStatus = "BLOCKED - Vulnerable/revoked boot loader on EFI partition (Event 1033).$bm Contact OEM."
}
elseif ($latestById.ContainsKey(1032)) {
    $evtStatus = 'BLOCKED - BitLocker recovery risk (Event 1032). Run Manage-bde -Protectors -Disable %systemdrive% -RebootCount 2 then reboot twice.'
}
elseif ($latestById.ContainsKey(1795)) {
    $ec = ''; if ($latestById[1795].Message -match '(?i)error\s+(0x[\dA-Fa-f]+|\d+)\s') { $ec = " Code: $($Matches[1])" }
    $evtStatus = "ERROR - Firmware error during Secure Boot update (Event 1795).$ec Contact device manufacturer."
}
elseif ($latestById.ContainsKey(1796)) {
    $ec = ''; if ($latestById[1796].Message -match '(?i)error\s+(0x[\dA-Fa-f]+|\d+)\s') { $ec = " Code: $($Matches[1])" }
    $evtStatus = "ERROR - Unexpected error (Event 1796).$ec Windows will retry on next restart."
}
elseif ($latestById.ContainsKey(1797)) {
    $evtStatus = 'ERROR - UEFI CA 2023 not in DB; DBX deferred pending DB update (Event 1797).'
}
elseif ($latestById.ContainsKey(1798)) {
    $evtStatus = 'ERROR - Default boot manager not signed by UEFI CA 2023; DBX deferred (Event 1798).'
}
elseif ($latestById.ContainsKey(1800)) {
    $evtStatus = 'PENDING - Reboot required (Event 1800).'
}
elseif ($latestById.ContainsKey(1801)) {
    $evtStatus = 'PENDING - Certificates in OS not yet written to firmware (Event 1801). See https://go.microsoft.com/fwlink/?linkid=2301018'
}
elseif ($latestById.ContainsKey(1045) -or $latestById.ContainsKey(1036)) {
    $evtStatus = 'IN_PROGRESS - DB/certificate update applied; DBX and boot manager steps may be pending.'
}
elseif ($latestById.ContainsKey(1034)) {
    $evtStatus = 'IN_PROGRESS - DBX update applied; DB and CA 2023 certificate steps may be pending.'
}


# ============================================================================
#  SECTION 3  -  OUTPUT
# ============================================================================

if ($OutputMode -eq 'CI') {

    # ---- CI MODE  -  single status token for ConfigMgr CI Discovery Script ----

    $ciValue = if ($null -ne $regDerivedStatus) {
        if ($regDerivedStatus -eq 'IN_PROGRESS') {
            if     ($latestById.ContainsKey(1801)) { 'PENDING_FIRMWARE' }
            elseif ($latestById.ContainsKey(1800)) { 'PENDING_REBOOT' }
            elseif ($evtStatus -like 'PENDING*')   { 'PENDING' }
            else                                   { 'IN_PROGRESS' }
        } else { $regDerivedStatus }
    } else {
        if     ($evtStatus -like 'COMPLETE*')    { 'COMPLETE' }
        elseif ($evtStatus -like 'BLOCKED*')     { 'BLOCKED' }
        elseif ($evtStatus -like 'ERROR*')       { 'ERROR' }
        elseif ($evtStatus -like 'PENDING*')     { 'PENDING' }
        elseif ($evtStatus -like 'IN_PROGRESS*') { 'IN_PROGRESS' }
        elseif ($evtStatus -like 'LOG_ACCESS*')  { 'LOG_ACCESS_ERR' }
        elseif ($evtStatus -like 'NO_EVENTS*') {
            if     ($null -ne $regCapable -and [int]$regCapable -ge 2) { 'COMPLETE_REG' }
            elseif ($null -ne $regCapable -and [int]$regCapable -ge 1) { 'PARTIAL_REG' }
            else   { 'NO_EVENTS' }
        }
        else { 'UNKNOWN' }
    }

    Write-Output $ciValue

}
elseif ($OutputMode -eq 'Collector') {

    # ---- COLLECTOR MODE  -  writes per-device JSON to $CollectorShare ----------

    [int[]] $deviceSpecificIds = @(1795, 1801, 1802, 1803, 1808)
    $deviceEvent  = $allEvents | Where-Object { $deviceSpecificIds -contains $_.Id } |
                    Select-Object -First 1
    $bucketFields = if ($deviceEvent) { Get-EventFields -Message $deviceEvent.Message }
                    else { [ordered]@{ DeviceAttributes=$null; BucketId=$null
                                       BucketConfidenceLevel=$null; UpdateType=$null; SkipReason=$null } }

    $statusToken = if ($null -ne $regDerivedStatus) {
        if ($regDerivedStatus -eq 'IN_PROGRESS') {
            if     ($evtStatus -like 'PENDING*')     { 'PENDING' }
            elseif ($latestById.ContainsKey(1801))   { 'PENDING_FIRMWARE' }
            elseif ($latestById.ContainsKey(1800))   { 'PENDING_REBOOT' }
            else                                     { 'IN_PROGRESS' }
        } else { $regDerivedStatus }
    } else {
        if     ($evtStatus -like 'COMPLETE*')    { 'COMPLETE' }
        elseif ($evtStatus -like 'BLOCKED*')     { 'BLOCKED' }
        elseif ($evtStatus -like 'ERROR*')       { 'ERROR' }
        elseif ($evtStatus -like 'PENDING*')     { 'PENDING' }
        elseif ($evtStatus -like 'IN_PROGRESS*') { 'IN_PROGRESS' }
        elseif ($evtStatus -like 'LOG_ACCESS*')  { 'LOG_ACCESS_ERR' }
        elseif ($evtStatus -like 'NO_EVENTS*') {
            if     ($null -ne $regCapable -and [int]$regCapable -ge 2) { 'COMPLETE_REG' }
            elseif ($null -ne $regCapable -and [int]$regCapable -ge 1) { 'PARTIAL_REG' }
            else   { 'NO_EVENTS' }
        }
        else { 'UNKNOWN' }
    }

    $confidenceLevel = if ($null -ne $regConfidence) { $regConfidence } else { $bucketFields.BucketConfidenceLevel }
    $bucketHash      = if ($null -ne $regBucketHash) { $regBucketHash } else { $bucketFields.BucketId }
    $confidenceSrc   = if ($null -ne $regConfidence) { 'Registry' } else { 'EventLog' }

    $payload = [ordered]@{
        # Identity
        ComputerName          = $env:COMPUTERNAME
        CollectedAt           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        # CA2023 status
        Status                = $statusToken
        RegDerivedStatus      = $regDerivedStatus
        StatusDetail          = $evtStatus
        RegStatus             = $regStatus
        RegError              = if ($null -ne $regError)      { [int]$regError }      else { $null }
        RegErrorEvent         = if ($null -ne $regErrorEvent) { [int]$regErrorEvent } else { $null }
        ConfidenceLevel       = $confidenceLevel
        ConfidenceLevelSource = $confidenceSrc
        BucketHash            = $bucketHash
        DeviceAttributes      = $bucketFields.DeviceAttributes
        UpdateType            = $bucketFields.UpdateType
        SkipReason            = $bucketFields.SkipReason
        # OS
        OSCaption             = $osCaption
        OSBuildNumber         = $osBuild
        # Hardware
        SystemManufacturer    = $sysManufacturer
        SystemModel           = $sysModel
        # BIOS
        BIOSManufacturer      = $biosManufacturer
        BIOSVersion           = $biosVersion
        BIOSVersionParsed     = $biosVersionParsed
        BIOSReleaseDate       = $biosReleaseDate
        # Platform
        IsVirtualMachine      = $isVirtualMachine
        SecureBootStatus      = $secureBootStatus
        # HP-specific additional check (CSP version SBKPFV3 string)
        CspVendor             = $cspVendor
        CspVersion            = $cspVersion
        IsHpDevice            = $isHpDevice
        HpSbkpfv3Present      = $hpSbkpfv3Present
        # Events
        EventCount            = $allEvents.Count
        LastEventId           = if ($allEvents.Count -gt 0) { $allEvents[0].Id } else { $null }
        LastEventTime         = if ($allEvents.Count -gt 0) {
                                    $allEvents[0].TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                                } else { $null }
    }

    if ($CollectorShare) {
        if (-not (Test-Path -LiteralPath $CollectorShare)) {
            Write-Output "ERROR - Share not reachable: $CollectorShare"
        } else {
            $outFile = Join-Path $CollectorShare "$($env:COMPUTERNAME).json"
            try {
                $payload | ConvertTo-Json -Depth 3 |
                    Set-Content -LiteralPath $outFile -Encoding UTF8 -Force -ErrorAction Stop
                Write-Output "OK - $outFile  Status: $($payload.Status)  SB: $($payload.SecureBootStatus)"
            }
            catch { Write-Output "ERROR - Cannot write $outFile : $($_.Exception.Message)" }
        }
    } else {
        $payload | ConvertTo-Json -Depth 3
    }

}
else {

    # ---- VERBOSE MODE  -  Run Scripts / manual use ------------------------------

    $eventRows = $allEvents |
        Select-Object -First $MaxEventDetail |
        ForEach-Object {
            $desc   = Get-EventDescription -Id $_.Id
            $fields = Get-EventFields -Message $_.Message
            $msg    = ($_.Message -replace '\r?\n', ' ' -replace '\s{2,}', ' ').Trim()
            if ($msg.Length -gt 220) { $msg = $msg.Substring(0, 220) + ' [...]' }
            [PSCustomObject]@{
                Time_UTC = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
                EventID  = $_.Id
                Level    = $_.LevelDisplayName
                Class    = $desc.StatusClass
                SkipRsn  = $fields.SkipReason
                RawMsg   = $msg
            }
        }

    $sep  = ('=' * 72)
    $sep2 = ('-' * 72)

    Write-Output $sep
    Write-Output '  SECURE BOOT CA 2023  -  FULL STATUS REPORT  (v3.0)'
    Write-Output "  Computer  : $env:COMPUTERNAME"
    Write-Output "  Collected : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    Write-Output $sep

    Write-Output ''
    Write-Output '  HARDWARE / OS'
    Write-Output $sep2
    Write-Output "  OS                    : $(if ($osCaption)        { $osCaption }        else { '(not available)' })"
    Write-Output "  OS Build              : $(if ($osBuild)          { $osBuild }          else { '(not available)' })"
    Write-Output "  System Manufacturer   : $(if ($sysManufacturer)  { $sysManufacturer }  else { '(not available)' })"
    Write-Output "  System Model          : $(if ($sysModel)         { $sysModel }         else { '(not available)' })"
    Write-Output "  BIOS Manufacturer     : $(if ($biosManufacturer) { $biosManufacturer } else { '(not available)' })"
    Write-Output "  BIOS Version (raw)    : $(if ($biosVersion)      { $biosVersion }      else { '(not available)' })"
    Write-Output "  BIOS Version (parsed) : $(if ($biosVersionParsed){ $biosVersionParsed} else { '(could not parse)' })"
    Write-Output "  BIOS Release Date     : $(if ($biosReleaseDate)  { $biosReleaseDate }  else { '(not available)' })"
    Write-Output "  Is Virtual Machine    : $isVirtualMachine"
    Write-Output "  Secure Boot State     : $secureBootStatus"

    if ($isHpDevice) {
        Write-Output "  HP SBKPFV3 Check      : $hpBiosStatus"
    }

    Write-Output ''
    Write-Output '  CA2023 REGISTRY (current state snapshot)'
    Write-Output $sep2
    Write-Output "  UEFICA2023Status      : $(if ($null -ne $regStatus)      { $regStatus }          else { '(not present - requires Nov 2025+ update)' })"
    Write-Output "  UEFICA2023Error       : $(if ($null -ne $regError)       { [int]$regError }      else { '(not present)' })"
    Write-Output "  UEFICA2023ErrorEvent  : $(if ($null -ne $regErrorEvent)  { [int]$regErrorEvent } else { '(not present)' })"
    Write-Output "  ConfidenceLevel       : $(if ($null -ne $regConfidence)  { $regConfidence }      else { '(not present - requires Nov 2025+ update)' })"
    Write-Output "  BucketHash            : $(if ($null -ne $regBucketHash)  { $regBucketHash }      else { '(not present - requires Nov 2025+ update)' })"
    Write-Output "  RegDerivedStatus      : $(if ($null -ne $regDerivedStatus){ $regDerivedStatus}   else { '(null - falling back to event log)' })"
    Write-Output "  Capable (ref only)    : $capableDesc"

    Write-Output ''
    Write-Output '  CA2023 EVENT LOG (System log / Microsoft-Windows-TPM-WMI)'
    Write-Output $sep2
    Write-Output "  Total matching events : $($allEvents.Count)"
    Write-Output "  Overall Status        : $evtStatus"

    if ($eventRows) {
        Write-Output ''
        Write-Output "  Recent events (newest first, up to $MaxEventDetail shown):"
        $eventRows | Format-Table -AutoSize -Property Time_UTC, EventID, Level, Class, SkipRsn |
            Out-String -Width 120 | Write-Output
    } else {
        Write-Output ''
        Write-Output '  No matching events found. Log may have rolled over or update not yet attempted.'
        Write-Output '  Use UEFICA2023Status and ConfidenceLevel in registry above as the primary signal.'
    }

    Write-Output $sep
}
