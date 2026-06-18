#Requires -Version 5.1
<#
.SYNOPSIS
    Merge-SecureBootCA2023Status_v3_0.ps1
    Aggregates per-device JSON files written by the v3.0 collector into a
    single combined JSON and CSV ready for import into the dashboard.

.DESCRIPTION
    Run this on a schedule (e.g. nightly via Task Scheduler or a ConfigMgr
    Package) on any server that has read access to $SourceShare.

    Each client device writes a {ComputerName}.json to $SourceShare when
    Get-SecureBootCA2023StatusFull_v3_0.ps1 runs in Collector mode.
    This script reads all those files and produces:

      SecureBootCA2023_v3_Combined.json   - full dataset for dashboard import
      SecureBootCA2023_v3_Combined.csv    - flat CSV for Excel / cross-reference

    BIOS COMPLIANCE
    ---------------------------------------------------------------------
    BiosReadyStatus is NOT computed here. The dashboard performs the HP/Dell
    table lookup live on import, using SystemManufacturer, SystemModel, and
    BIOSVersionParsed from the device JSON. Update the dashboard HTML to
    refresh the compatibility tables; no aggregator re-run needed.

    SHARE PERMISSIONS (recommended)
    ---------------------------------------------------------------------
    Domain Computers    : Write only (Create Files / Write Data)
                          No Read, No List
    Domain Admins       : Full Control
    Service account     : Read (account running this aggregator)
    ---------------------------------------------------------------------

    SCHEDULING
    ---------------------------------------------------------------------
    Recommended: nightly Task Scheduler job on a management server.
    The combined files are then available for the next morning's
    dashboard refresh.
    ---------------------------------------------------------------------

.NOTES
    Collector  : Get-SecureBootCA2023StatusFull_v3_0.ps1
    BIOS tables: embedded in SecureBoot_CA2023_Dashboard.html (update HTML to refresh)
    Min PS     : 5.1
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

# Share where per-device JSON files are stored (must be readable by this script)
[string] $SourceShare  = '\\INFRANBX271\Test$'

# Where to write the combined output files
# Can be the same share (in a subdirectory) or a separate location
[string] $OutputFolder = '\\INFRANBX271\Test$\Combined'

# Devices whose JSON is older than this many days are flagged Stale = $true
[int]    $StaleDays    = 7


# ============================================================================
#  CLASSIFICATION HELPERS
# ============================================================================

function Get-StatusGroup {
    <#
    .SYNOPSIS
        Maps the collector Status token to a broad group for dashboard filtering.
        Groups: Compliant | ActionRequired | InProgress | Unknown
    #>
    param([string] $Status)
    switch ($Status) {
        'COMPLETE'                 { return 'Compliant' }
        'COMPLETE_REG'             { return 'Compliant' }
        'IN_PROGRESS'              { return 'InProgress' }
        'PARTIAL_REG'              { return 'InProgress' }
        'PENDING'                  { return 'InProgress' }
        'PENDING_REBOOT'           { return 'InProgress' }
        'PENDING_FIRMWARE'         { return 'InProgress' }
        'BLOCKED'                  { return 'ActionRequired' }
        'BLOCKED_BITLOCKER'        { return 'ActionRequired' }
        'BLOCKED_BOOTLOADER'       { return 'ActionRequired' }
        'BLOCKED_FIRMWARE_ISSUE'   { return 'ActionRequired' }
        'BLOCKED_NO_KEK'           { return 'ActionRequired' }
        'ERROR'                    { return 'ActionRequired' }
        'ERROR_FIRMWARE'           { return 'ActionRequired' }
        'ERROR_UNEXPECTED'         { return 'ActionRequired' }
        'ERROR_DB_MISSING'         { return 'ActionRequired' }
        'ERROR_BOOTMGR_UNSIGNED'   { return 'ActionRequired' }
        'LOG_ACCESS_ERR'           { return 'ActionRequired' }
        'NOT_STARTED'              { return 'Unknown' }
        'NO_EVENTS'                { return 'Unknown' }
        default                    { return 'Unknown' }
    }
}

function Get-ConfidenceGroup {
    <#
    .SYNOPSIS
        Maps the ConfidenceLevel free-text value to a short token.
        Values as documented in Microsoft KB 5016061 / KB 5068202.
    #>
    param([string] $Level)
    if     ([string]::IsNullOrEmpty($Level))               { return $null }
    elseif ($Level -match '(?i)high confidence')            { return 'HighConfidence' }
    elseif ($Level -match '(?i)temporarily paused')         { return 'TemporarilyPaused' }
    elseif ($Level -match '(?i)not supported')              { return 'NotSupported' }
    elseif ($Level -match '(?i)under observation')          { return 'UnderObservation' }
    elseif ($Level -match '(?i)no data observed')           { return 'NoData' }
    else                                                    { return 'Other' }
}


# ============================================================================
#  MAIN  -  READ SOURCE FILES
# ============================================================================

Write-Output "Merge-SecureBootCA2023Status v3.0"
Write-Output "Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Source   : $SourceShare"
Write-Output ""

# Validate share access before doing any work
if (-not (Test-Path -LiteralPath $SourceShare)) {
    Write-Error "Source share not accessible: $SourceShare"
    exit 1
}

# Read all per-device JSON files; skip subdirectories
$jsonFiles = Get-ChildItem -LiteralPath $SourceShare -Filter '*.json' -File |
    Sort-Object Name

Write-Output "Found    : $($jsonFiles.Count) JSON file(s)"

$staleCutoff  = (Get-Date).ToUniversalTime().AddDays(-$StaleDays)
$allDevices   = [System.Collections.Generic.List[PSCustomObject]]::new()
$parseErrors  = 0
$skippedFiles = [System.Collections.Generic.List[string]]::new()

foreach ($file in $jsonFiles) {
    try {
        $raw    = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
        $device = $raw | ConvertFrom-Json -ErrorAction Stop

        # Skip the combined output file if it landed in the same folder
        if ($device.PSObject.Properties.Name -contains '_MergedBy') { continue }

        # -- Staleness check --------------------------------------------------
        $isStale = $false
        if ($device.CollectedAt) {
            try {
                $ts      = [datetime]::Parse(
                    $device.CollectedAt, $null,
                    [System.Globalization.DateTimeStyles]::RoundtripKind)
                $isStale = $ts -lt $staleCutoff
            }
            catch { $isStale = $true }
        }
        else { $isStale = $true }


        # -- Build enriched flat row ------------------------------------------
        $row = [ordered]@{

            # Identity
            ComputerName          = $device.ComputerName
            CollectedAt           = $device.CollectedAt
            Stale                 = $isStale

            # CA2023 status
            Status                = $device.Status
            StatusGroup           = Get-StatusGroup -Status $device.Status
            StatusDetail          = $device.StatusDetail
            RegDerivedStatus      = $device.RegDerivedStatus

            # Registry
            RegStatus             = $device.RegStatus
            RegError              = $device.RegError
            RegErrorEvent         = $device.RegErrorEvent
            RegCapable            = $device.RegCapable

            # Confidence & bucket
            ConfidenceLevel       = $device.ConfidenceLevel
            ConfidenceLevelSource = $device.ConfidenceLevelSource
            ConfidenceGroup       = Get-ConfidenceGroup -Level $device.ConfidenceLevel
            BucketHash            = $device.BucketHash
            DeviceAttributes      = $device.DeviceAttributes
            UpdateType            = $device.UpdateType
            SkipReason            = $device.SkipReason

            # Event log
            EventCount            = $device.EventCount
            LastEventId           = $device.LastEventId
            LastEventTime         = $device.LastEventTime

            # OS  (v3.0; null for v2.1 files)
            OSCaption             = $device.OSCaption
            OSBuildNumber         = $device.OSBuildNumber

            # Hardware  (v3.0; null for v2.1 files)
            SystemManufacturer    = $device.SystemManufacturer
            SystemModel           = $device.SystemModel

            # BIOS info  (v3.0; null for v2.1 files)
            BIOSManufacturer      = $device.BIOSManufacturer
            BIOSVersion           = $device.BIOSVersion
            BIOSVersionParsed     = $device.BIOSVersionParsed
            BIOSReleaseDate       = $device.BIOSReleaseDate

            # Platform  (v3.0; null / default for v2.1 files)
            IsVirtualMachine      = $device.IsVirtualMachine
            SecureBootStatus      = $device.SecureBootStatus


            # HP-specific legacy fields (present in both v2.1 and v3.0)
            CspVendor             = $device.CspVendor
            CspVersion            = $device.CspVersion
            IsHpDevice            = $device.IsHpDevice
            HpSbkpfv3Present      = $device.HpSbkpfv3Present
        }

        $allDevices.Add([PSCustomObject]$row)
    }
    catch {
        Write-Warning "Parse error  - $($file.Name): $($_.Exception.Message)"
        $skippedFiles.Add($file.Name)
        $parseErrors++
    }
}


# ============================================================================
#  OUTPUT FILES
# ============================================================================

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$ts          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$jsonOutPath = Join-Path $OutputFolder 'SecureBootCA2023_v3_Combined.json'
$csvOutPath  = Join-Path $OutputFolder 'SecureBootCA2023_v3_Combined.csv'

# -- Combined JSON ------------------------------------------------------------
$jsonWrapper = [ordered]@{
    _MergedBy    = 'Merge-SecureBootCA2023Status_v3_0.ps1'
    _GeneratedAt = $ts
    _DeviceCount = $allDevices.Count
    _StaleCount  = ($allDevices | Where-Object { $_.Stale }).Count
    _ParseErrors = $parseErrors
    Devices      = $allDevices
}

$jsonWrapper | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $jsonOutPath -Encoding UTF8

# -- Combined CSV -------------------------------------------------------------
$allDevices |
    Select-Object ComputerName, CollectedAt, Stale,
        Status, StatusGroup, StatusDetail, RegDerivedStatus,
        RegStatus, RegError, RegErrorEvent, RegCapable,
        ConfidenceLevel, ConfidenceLevelSource, ConfidenceGroup,
        BucketHash, DeviceAttributes, UpdateType, SkipReason,
        EventCount, LastEventId, LastEventTime,
        OSCaption, OSBuildNumber,
        SystemManufacturer, SystemModel,
        BIOSManufacturer, BIOSVersion, BIOSVersionParsed, BIOSReleaseDate,
        IsVirtualMachine, SecureBootStatus,
        CspVendor, CspVersion, IsHpDevice, HpSbkpfv3Present |
    Export-Csv -LiteralPath $csvOutPath -NoTypeInformation -Encoding UTF8


# ============================================================================
#  SUMMARY
# ============================================================================

$total = $allDevices.Count
$stale = ($allDevices | Where-Object { $_.Stale }).Count
$sep   = '-' * 52

Write-Output ""
Write-Output $sep
Write-Output ("Merged   : {0} device(s)  ({1} stale, >{2}d old)" -f $total, $stale, $StaleDays)
Write-Output ("Errors   : {0} parse error(s){1}" -f $parseErrors,
    $(if ($parseErrors -gt 0) { '  - ' + ($skippedFiles -join ', ') } else { '' }))
Write-Output $sep

# CA2023 Status breakdown
Write-Output ""
Write-Output "CA2023 Status breakdown:"
$allDevices | Group-Object Status | Sort-Object Count -Descending | ForEach-Object {
    Write-Output ("  {0,-25} {1,5}  {2}" -f $_.Name, $_.Count,
        ('|' * [Math]::Min([int]($_.Count / [Math]::Max($total, 1) * 40), 40)))
}

# Confidence Level breakdown (only for devices that have it)
$withConf = $allDevices | Where-Object { $_.ConfidenceLevel }
if ($withConf) {
    Write-Output ""
    Write-Output "Confidence Level breakdown ($($withConf.Count) device(s) with data):"
    $withConf | Group-Object ConfidenceLevel | Sort-Object Count -Descending | ForEach-Object {
        Write-Output ("  {0,-45} {1,5}" -f $_.Name, $_.Count)
    }
}

# Virtual machine callout
if ($vms -gt 0) {
    Write-Output ""
    Write-Output "Virtual machines: $vms (BIOS compliance check not applicable)"
}

Write-Output ""
Write-Output $sep
Write-Output "Output   : $jsonOutPath"
Write-Output "           $csvOutPath"
Write-Output "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
