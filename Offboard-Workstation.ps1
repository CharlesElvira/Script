<#
.SYNOPSIS
    Workstation offboarding - removes MSP management/security tooling and hands
    the machine back to its owner with local administrator access.

.DESCRIPTION
    Designed to be pushed MANUALLY as a Datto RMM Script component (Windows,
    PowerShell, runs as SYSTEM). Never attach this to a policy or schedule.

    Order of operations:
      1. Uninstall Huntress          (portal disengage MUST be done first)
      2. Uninstall Cove Data Protection (Backup Manager)
      3. Uninstall Datto Backup      (Datto Windows Agent / Endpoint Backup)
      4. Grant local admin rights    (existing users and/or a generic account)
      5. Stage a run-once scheduled task to remove the Datto RMM agent at next boot

    The Datto RMM agent is removed LAST, by scheduled task, because a component
    cannot uninstall the agent that is executing it.

.PARAMETER AdminMode
    ExistingUsers  - add every enabled non-builtin local user to Administrators
    GenericAccount - create a single generic local admin
    Both           - do both (default)

.PARAMETER GenericUserName
    Name of the generic account. Default 'LocalAdmin'.

.PARAMETER CredentialPath
    Folder for the handover credential file. Default 'C:\temp'.

.PARAMETER DryRun
    Log every action without performing it. Run this first.

.EXAMPLE
    .\Offboard-Workstation.ps1 -DryRun
    .\Offboard-Workstation.ps1
    .\Offboard-Workstation.ps1 -AdminMode GenericAccount -GenericUserName 'OwnerAdmin'
	.\Offboard-Workstation.ps1 -SkipCove
.NOTES
    PRE-FLIGHT (do these in the portals BEFORE running):
      - Huntress: remove/disengage the agent in the Huntress dashboard, allow up
        to 30 minutes for the Tamper Protection exclusion to reach the endpoint,
        and leave the machine online during that window.
      - Datto RMM: confirm Agent Uninstall Protection is not enabled for the site.
      - Cove / Datto Backup: cancel or release the protected-device licence.
#>

[CmdletBinding()]
param(
    [ValidateSet('ExistingUsers', 'GenericAccount', 'Both')]
    [string] $AdminMode       = 'Both',

    [string] $GenericUserName = 'LocalAdmin',

    [string] $CredentialPath  = 'C:\temp',

    # Uninstall token from the Datto EDR platform. REQUIRED to remove Datto EDR /
    # Datto Endpoint Security - the agent is tamper-protected and will not come
    # off without it. Get it from the EDR portal before running.
    [string] $DattoEdrToken   = '',

    [switch] $SkipHuntress,
    [switch] $SkipCove,
    [switch] $SkipDattoBackup,
    [switch] $SkipDNSFilter,
    [switch] $SkipDattoEdr,
    [switch] $SkipAdminRights,
    [switch] $SkipRmmRemoval,

    [switch] $DryRun
)

# Datto RMM component variables override parameters when present
if ($env:AdminMode)       { $AdminMode       = $env:AdminMode }
if ($env:GenericUserName) { $GenericUserName = $env:GenericUserName }
if ($env:DattoEdrToken)   { $DattoEdrToken   = $env:DattoEdrToken }
if ($env:DryRun -eq 'true') { $DryRun = $true }

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$StageDir = 'C:\ProgramData\Offboard'
$LogFile  = Join-Path $StageDir ("Offboard-{0}.log" -f $env:COMPUTERNAME)
$Summary  = [ordered]@{}

# ---------------------------------------------------------------- helpers

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK','DRY')][string]$Level = 'INFO')
    $line = '{0}  [{1,-5}]  {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    try {
        if (-not (Test-Path $StageDir)) { New-Item -ItemType Directory -Path $StageDir -Force | Out-Null }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Write-Section {
    param([string]$Title)
    Write-Log ('=' * 62)
    Write-Log $Title
    Write-Log ('=' * 62)
}

function Get-InstalledApp {
    <# Returns uninstall-registry entries whose DisplayName matches $Pattern. #>
    param([Parameter(Mandatory)][string]$Pattern)
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($root in $roots) {
        Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match $Pattern }
    }
}

function Invoke-SilentUninstall {
    <#
      Uninstalls by registry entry. Prefers QuietUninstallString (Cove's own
      documentation points here), otherwise derives the correct silent switch
      from the installer technology.
    #>
    param(
        [Parameter(Mandatory)] $App,
        [string] $Label = 'application'
    )

    $exe = $null; $argLine = $null

    if ($App.QuietUninstallString) {
        $q = $App.QuietUninstallString.Trim()
        if ($q -match '^"([^"]+)"\s*(.*)$') { $exe = $Matches[1]; $argLine = $Matches[2] }
        else { $parts = $q -split '\s+', 2; $exe = $parts[0]; $argLine = $parts[1] }
    }
    elseif ($App.UninstallString) {
        $u = $App.UninstallString.Trim()
        if ($u -match '^"([^"]+)"\s*(.*)$') { $exe = $Matches[1]; $argLine = $Matches[2] }
        else { $parts = $u -split '\s+', 2; $exe = $parts[0]; $argLine = $parts[1] }

        if ($exe -match 'msiexec')            { $argLine = ($argLine -replace '/I', '/X') + ' /qn /norestart' }
        elseif ($exe -match 'unins\d+\.exe$') { $argLine = "$argLine /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" }  # Inno Setup
        else                                  { $argLine = "$argLine /S" }                                        # NSIS
    }

    if (-not $exe) { Write-Log "No uninstall string for $Label." 'WARN'; return $false }
    if (-not (Test-Path $exe) -and $exe -notmatch 'msiexec') {
        Write-Log "Uninstaller missing on disk: $exe" 'WARN'; return $false
    }

    Write-Log "Command: `"$exe`" $argLine"
    if ($DryRun) { Write-Log "DRY RUN - not executed." 'DRY'; return $true }

    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argLine -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -in 0, 3010, 1605, 1614) {
            Write-Log "$Label removed (exit $($p.ExitCode))." 'OK'; return $true
        }
        Write-Log "$Label uninstaller returned $($p.ExitCode)." 'WARN'; return $false
    } catch {
        Write-Log "$Label uninstall failed: $($_.Exception.Message)" 'ERROR'; return $false
    }
}

function Remove-Product {
    param(
        [Parameter(Mandatory)][string] $Pattern,
        [Parameter(Mandatory)][string] $Label,
        [string[]] $FallbackPaths = @(),
        [string]   $FallbackArgs  = '/S',
        [string[]] $ServicesToStop = @(),
        # Disable before stopping - needed where a watchdog service revives the agent
        [switch]   $DisableServices
    )

    Write-Section "Removing: $Label"

    # Order matters: pass watchdog/service-manager entries FIRST.
    foreach ($svc in $ServicesToStop) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        if ($DisableServices) {
            Write-Log "Disabling service '$svc'."
            if (-not $DryRun) { Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue }
        }
        if ($s.Status -eq 'Running') {
            Write-Log "Stopping service '$svc'."
            if (-not $DryRun) { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
        }
    }

    $apps = @(Get-InstalledApp -Pattern $Pattern)
    if ($apps.Count -eq 0) {
        Write-Log "$Label not found in the uninstall registry."
    } else {
        foreach ($a in $apps) {
            Write-Log "Found: $($a.DisplayName) $($a.DisplayVersion)"
            if (Invoke-SilentUninstall -App $a -Label $Label) {
                Start-Sleep -Seconds 5
            }
        }
    }

    # fallback for products with no/broken ARP entry
    foreach ($path in $FallbackPaths) {
        if (Test-Path $path) {
            Write-Log "Fallback uninstaller: $path $FallbackArgs"
            if ($DryRun) { Write-Log "DRY RUN - not executed." 'DRY'; continue }
            try {
                $p = Start-Process -FilePath $path -ArgumentList $FallbackArgs -Wait -PassThru -WindowStyle Hidden
                Write-Log "Fallback exit code: $($p.ExitCode)"
            } catch { Write-Log "Fallback failed: $($_.Exception.Message)" 'WARN' }
            Start-Sleep -Seconds 5
        }
    }

    $still = @(Get-InstalledApp -Pattern $Pattern)
    if ($DryRun) {
        $Summary[$Label] = 'DRY RUN'
    } elseif ($still.Count -eq 0) {
        Write-Log "${Label}: confirmed removed." 'OK'; $Summary[$Label] = 'Removed'
    } else {
        Write-Log "${Label}: STILL PRESENT - needs manual removal." 'ERROR'; $Summary[$Label] = 'FAILED'
    }
}

function New-RandomPassword {
    param([int]$Length = 18)
    # ambiguous characters (0/O, 1/l/I) excluded so it can be read off a screen
    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!#$%&*+-=?@'
    )
    $all = -join $sets

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] 4
    $pick = {
        param([string]$Set)
        $rng.GetBytes($buf)
        $Set[ [BitConverter]::ToUInt32($buf, 0) % $Set.Length ]
    }

    # guarantee one character from each class, then fill to length
    $chars = @( foreach ($s in $sets) { & $pick $s } )
    while ($chars.Count -lt $Length) { $chars += (& $pick $all) }

    # shuffle so the guaranteed characters aren't always in front
    -join ($chars | Sort-Object { $rng.GetBytes($buf); [BitConverter]::ToUInt32($buf, 0) })
}

# ---------------------------------------------------------------- start

if (-not (Test-Path $StageDir)) { New-Item -ItemType Directory -Path $StageDir -Force | Out-Null }

Write-Section "OFFBOARDING $env:COMPUTERNAME"
Write-Log "Started: $(Get-Date)"
Write-Log "Admin mode: $AdminMode"
if ($DryRun) { Write-Log 'DRY RUN - no changes will be made.' 'DRY' }

Write-Log ''
Write-Log 'REMINDER: Huntress must already be disengaged in the portal, with the'
Write-Log 'Tamper Protection exclusion delivered, or its uninstall will fail.'
Write-Log ''

# ---------------------------------------------------------------- 1. Huntress
if (-not $SkipHuntress) {
    Remove-Product -Pattern '^Huntress' -Label 'Huntress' `
        -ServicesToStop @('HuntressAgent', 'HuntressUpdater', 'HuntressRio') `
        -FallbackPaths @(
            'C:\Program Files\Huntress\Uninstall.exe',
            'C:\Program Files (x86)\Huntress\Uninstall.exe'
        ) -FallbackArgs '/S'

    # Fallback: Huntress' own deployment script. Needs no account/org key to
    # uninstall, and is more thorough than the bare uninstaller. It still cannot
    # defeat Tamper Protection - that exclusion has to come from the portal.
    if ($Summary['Huntress'] -eq 'FAILED' -and -not $DryRun) {
        Write-Log 'Trying the official Huntress uninstall script.' 'WARN'
        $hs = Join-Path $StageDir 'InstallHuntress.ps1'
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/huntresslabs/deployment-scripts/main/Powershell/InstallHuntress.powershellv2.ps1' -OutFile $hs
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hs -uninstall 2>&1 | ForEach-Object { Write-Log "  huntress: $_" }
            Start-Sleep -Seconds 20
            if (-not (Get-InstalledApp -Pattern '^Huntress')) {
                Write-Log 'Huntress removed by official script.' 'OK'; $Summary['Huntress'] = 'Removed (official script)'
            } else {
                Write-Log 'Huntress still present. Tamper Protection is likely still active -' 'ERROR'
                Write-Log 'remove the agent in the Huntress portal, keep the machine online for'  'ERROR'
                Write-Log 'up to 30 minutes, then re-run. Or raise a Huntress support ticket.'    'ERROR'
            }
        } catch { Write-Log "Could not download/run the Huntress script: $($_.Exception.Message)" 'ERROR' }
    }
} else { $Summary['Huntress'] = 'Skipped' }

# ---------------------------------------------------------------- 1b. Datto EDR
# MUST run before Datto RMM removal. When EDR is deployed through the RMM
# integration its binaries live under C:\ProgramData\CentraStage\AEMAgent\...,
# so removing the RMM agent first deletes the uninstaller and strands a
# tamper-protected service with no supported way to remove it.
# Also requires working network - the agent validates the token online.
if (-not $SkipDattoEdr) {
    Write-Section 'Removing: Datto EDR / Datto Endpoint Security'

    $edrPaths = @(
        'C:\Program Files\Infocyte\Agent\agent.exe',
        'C:\Program Files (x86)\Infocyte\Agent\agent.exe',
        'C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\agent.exe',
        'C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetication\agent.exe'  # vendor typo, seen in the wild
    )
    $edrExe = $edrPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $edrExe) {
        Write-Log 'Datto EDR agent not found on this device.'
        $Summary['Datto EDR'] = 'Not present'
    }
    elseif (-not $DattoEdrToken) {
        Write-Log "Datto EDR found at $edrExe" 'ERROR'
        Write-Log 'No uninstall token supplied. Datto EDR is tamper-protected and'  'ERROR'
        Write-Log 'CANNOT be removed without the token from the EDR platform.'      'ERROR'
        Write-Log 'Get it from the EDR portal and re-run with -DattoEdrToken.'      'ERROR'
        Write-Log 'Preferred alternative: uninstall from the EDR platform, which'   'ERROR'
        Write-Log 'also releases the licence and clears the device from inventory.' 'ERROR'
        $Summary['Datto EDR'] = 'FAILED - token required'
    }
    else {
        Write-Log "Datto EDR agent: $edrExe"
        Write-Log 'Running: agent.exe --uninstall <token redacted>'
        if ($DryRun) {
            Write-Log 'DRY RUN - not executed.' 'DRY'
            $Summary['Datto EDR'] = 'DRY RUN'
        } else {
            try {
                $p = Start-Process -FilePath $edrExe -ArgumentList "--uninstall $DattoEdrToken" `
                        -PassThru -WindowStyle Hidden
                if ($p.WaitForExit(600000)) { Write-Log "Exit code: $($p.ExitCode)" }
                else { Write-Log 'EDR uninstaller still running after 10 minutes - leaving it.' 'WARN' }

                Start-Sleep -Seconds 20
                $left = @($edrPaths | Where-Object { Test-Path $_ })
                if ($left.Count -eq 0) {
                    Write-Log 'Datto EDR removed.' 'OK'; $Summary['Datto EDR'] = 'Removed'
                } else {
                    Write-Log 'Datto EDR still present - check the token is correct and the' 'ERROR'
                    Write-Log 'device has internet access (the token is validated online).'  'ERROR'
                    $Summary['Datto EDR'] = 'FAILED'
                }
            } catch {
                Write-Log "Datto EDR uninstall failed: $($_.Exception.Message)" 'ERROR'
                $Summary['Datto EDR'] = 'FAILED'
            }
        }
    }
} else { $Summary['Datto EDR'] = 'Skipped' }

# ---------------------------------------------------------------- 2. Cove
if (-not $SkipCove) {
    Remove-Product -Pattern 'Backup Manager|Cove Data Protection' -Label 'Cove Data Protection' `
        -ServicesToStop @('BackupServiceController', 'ProcessController') `
        -FallbackPaths @(
            'C:\Program Files\Backup Manager\unins000.exe',
            'C:\Program Files (x86)\Backup Manager\unins000.exe'
        ) -FallbackArgs '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
} else { $Summary['Cove Data Protection'] = 'Skipped' }

# ---------------------------------------------------------------- 3. Datto Backup
if (-not $SkipDattoBackup) {
    Remove-Product -Pattern 'Datto Windows Agent|Datto Endpoint Backup|Datto Backup' -Label 'Datto Backup' `
        -ServicesToStop @('DattoBackupAgent', 'Datto Windows Agent', 'dattobackupagent') `
        -FallbackPaths @(
            'C:\Program Files (x86)\Datto\Datto Windows Agent\unins000.exe',
            'C:\Program Files\Datto\Datto Windows Agent\unins000.exe'
        ) -FallbackArgs '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
} else { $Summary['Datto Backup'] = 'Skipped' }

# ---------------------------------------------------------------- 3b. DNSFilter
if (-not $SkipDNSFilter) {
    # The Service Manager is a watchdog that restarts the agent, so it must be
    # disabled and stopped FIRST or the uninstall loses.
    Remove-Product -Pattern '^(DNSFilter Agent|DNS Agent)$' -Label 'DNSFilter Roaming Client' `
        -DisableServices `
        -ServicesToStop @(
            'DNSFilter Agent Service Manager',
            'DNS Agent Service Manager',
            'DNSFilter Agent',
            'DNS Agent'
        ) `
        -FallbackPaths @(
            'C:\Program Files\DNSFilter Agent\uninstall.exe',
            'C:\Program Files (x86)\DNSFilter Agent\uninstall.exe'
        ) -FallbackArgs '/S'

    # Leftover config
    foreach ($k in 'HKLM:\SOFTWARE\DNSFilter', 'HKLM:\SOFTWARE\WOW6432Node\DNSFilter') {
        if (Test-Path $k) {
            Write-Log "Removing registry key: $k"
            if (-not $DryRun) { Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # CRITICAL: the agent points every adapter at its own loopback listener
    # (127.0.0.2). Left as-is, the machine has no working DNS once the agent is
    # gone. Reset every physical adapter back to DHCP.
    Write-Log 'Resetting adapter DNS to DHCP.'
    if (-not $DryRun) {
        Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
          Where-Object Status -eq 'Up' | ForEach-Object {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction Stop
                Write-Log "  reset: $($_.Name)" 'OK'
            } catch { Write-Log "  could not reset $($_.Name): $($_.Exception.Message)" 'WARN' }
        }
        ipconfig /flushdns | Out-Null

        $dns = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.ServerAddresses -match '^127\.' })
        if ($dns) {
            Write-Log 'WARNING: an adapter still points at a loopback DNS address.' 'ERROR'
            Write-Log 'Set DNS manually before handover or the machine has no internet.' 'ERROR'
        } else {
            Write-Log 'No adapter is pointing at loopback DNS.' 'OK'
        }
    }
} else { $Summary['DNSFilter Roaming Client'] = 'Skipped' }

# ---------------------------------------------------------------- 4. Local admin
$credFile = $null

if (-not $SkipAdminRights) {
    Write-Section 'Granting local administrator access'

    $adminGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name   # locale-safe
    Write-Log "Administrators group resolved as '$adminGroup'."

    $builtIn = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount','krbtgt')
    $promoted = @()

    if ($AdminMode -in 'ExistingUsers', 'Both') {
        $users = Get-LocalUser | Where-Object { $_.Enabled -and $builtIn -notcontains $_.Name }
        if (-not $users) { Write-Log 'No eligible existing local users found.' 'WARN' }
        foreach ($u in $users) {
            try {
                $isMember = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -like "*\$($u.Name)" -or $_.Name -eq $u.Name }
                if ($isMember) { Write-Log "$($u.Name) is already an administrator."; continue }
                Write-Log "Adding $($u.Name) to $adminGroup."
                if (-not $DryRun) { Add-LocalGroupMember -Group $adminGroup -Member $u.Name -ErrorAction Stop }
                $promoted += $u.Name
            } catch { Write-Log "Could not promote $($u.Name): $($_.Exception.Message)" 'WARN' }
        }
    }

    if ($AdminMode -in 'GenericAccount', 'Both') {
        $pw = New-RandomPassword -Length 18
        $sec = ConvertTo-SecureString $pw -AsPlainText -Force

        try {
            $existing = Get-LocalUser -Name $GenericUserName -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Log "Local user '$GenericUserName' exists - resetting password."
                if (-not $DryRun) {
                    Set-LocalUser -Name $GenericUserName -Password $sec -PasswordNeverExpires $true
                    Enable-LocalUser -Name $GenericUserName
                }
            } else {
                Write-Log "Creating local user '$GenericUserName'."
                if (-not $DryRun) {
                    New-LocalUser -Name $GenericUserName -Password $sec `
                        -FullName 'Local Administrator' `
                        -Description 'Created during MSP offboarding' `
                        -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
                }
            }
            if (-not $DryRun) {
                Add-LocalGroupMember -Group $adminGroup -Member $GenericUserName -ErrorAction SilentlyContinue
            }

            # write the handover credential file
            if (-not (Test-Path $CredentialPath)) { New-Item -ItemType Directory -Path $CredentialPath -Force | Out-Null }
            $credFile = Join-Path $CredentialPath 'OFFBOARD-CREDENTIALS.txt'

            $body = @"
================================================================
  LOCAL ADMINISTRATOR CREDENTIALS
  $env:COMPUTERNAME
  Created $(Get-Date -Format 'yyyy-MM-dd HH:mm')
================================================================

  Username : $env:COMPUTERNAME\$GenericUserName
  Password : $pw

  This computer is no longer covered by a managed services
  agreement. Remote monitoring, managed backup, and managed
  security software have been removed.

  >> CHANGE THIS PASSWORD AFTER FIRST SIGN-IN.
  >> DELETE THIS FILE ONCE THE PASSWORD HAS BEEN CHANGED.

  Existing local accounts also granted administrator rights:
$(if ($promoted) { ($promoted | ForEach-Object { "    - $_" }) -join "`r`n" } else { '    (none)' })

================================================================
"@
            if ($DryRun) {
                Write-Log "DRY RUN - would write $credFile" 'DRY'
            } else {
                Set-Content -Path $credFile -Value $body -Encoding UTF8
                Write-Log "Credentials written to $credFile" 'OK'
            }
            $Summary['Generic admin account'] = "$GenericUserName (see $credFile)"
        } catch {
            Write-Log "Generic account failed: $($_.Exception.Message)" 'ERROR'
            $Summary['Generic admin account'] = 'FAILED'
        }
    }

    if ($promoted) { $Summary['Promoted existing users'] = ($promoted -join ', ') }
} else { $Summary['Local admin'] = 'Skipped' }

# ---------------------------------------------------------------- 5. Datto RMM (post-reboot)
if (-not $SkipRmmRemoval) {
    Write-Section 'Staging Datto RMM removal for next reboot'

    # Guard: never remove the RMM agent while Datto EDR is still installed under
    # the CentraStage tree - it would delete EDR's uninstaller and leave a
    # tamper-protected service with no supported removal path.
    $edrStillThere = @(
        'C:\Program Files\Infocyte\Agent\agent.exe',
        'C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\agent.exe',
        'C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetication\agent.exe'
    ) | Where-Object { Test-Path $_ }

    if ($edrStillThere) {
        Write-Log 'ABORTING Datto RMM removal - Datto EDR is still installed:' 'ERROR'
        $edrStillThere | ForEach-Object { Write-Log "  $_" 'ERROR' }
        Write-Log 'Removing the RMM agent now would delete EDR''s uninstaller and'  'ERROR'
        Write-Log 'strand a tamper-protected service. Remove Datto EDR first, then' 'ERROR'
        Write-Log 're-run this script.'                                             'ERROR'
        $Summary['Datto RMM removal'] = 'ABORTED - remove Datto EDR first'
        $SkipRmmRemoval = $true
    }
}

if (-not $SkipRmmRemoval) {

    $removerPath = Join-Path $StageDir 'Remove-DattoRMM.ps1'
    $taskName    = 'Offboard-Remove-DattoRMM'

    $remover = @'
# Removes the Datto RMM agent, then deletes its own scheduled task.
# Staged by Offboard-Workstation.ps1. Runs once at startup as SYSTEM.

$log = 'C:\ProgramData\Offboard\Remove-DattoRMM.log'
function L($m) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    Add-Content -Path $log -Value $line -Encoding UTF8
}

L '--- Datto RMM removal starting ---'
Start-Sleep -Seconds 120   # let the OS finish booting

# --- DNSFilter sweep + DNS reset ------------------------------------------
# Runs BEFORE the Datto RMM uninstall so the machine has working name
# resolution while the rest of this executes, and so we still have a log if
# something goes wrong. The DNSFilter Service Manager can revive the agent
# across a reboot, so disable it again here before checking DNS.
L 'Checking for DNSFilter services after reboot.'
foreach ($svc in 'DNSFilter Agent Service Manager','DNS Agent Service Manager','DNSFilter Agent','DNS Agent') {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        L "  found '$svc' (status $($s.Status)) - disabling and stopping"
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    }
}

L 'Resetting adapter DNS to DHCP.'
try {
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
      Where-Object Status -eq 'Up' | ForEach-Object {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction Stop
            L "  reset: $($_.Name)"
        } catch { L "  could not reset $($_.Name): $($_.Exception.Message)" }
      }
    ipconfig /flushdns | Out-Null

    $bad = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.ServerAddresses -match '^127\.' }
    if ($bad) {
        L 'WARNING: an adapter still points at a loopback DNS address.'
        L 'Set DNS manually before handover or this machine has no internet.'
    } else {
        L 'DNS OK - no loopback resolvers remain.'
    }
} catch { L "DNS reset failed: $($_.Exception.Message)" }

L '--- proceeding to Datto RMM removal ---'

foreach ($svc in 'CagService','AEMAgent') {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) { L "Stopping $svc"; Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
}

$done = $false

# 1) registry-driven
$roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($root in $roots) {
    Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -match 'Datto RMM|CentraStage|AEM Agent' } |
      ForEach-Object {
        $u = $_.QuietUninstallString; if (-not $u) { $u = $_.UninstallString }
        if ($u) {
            if ($u -match '^"([^"]+)"\s*(.*)$') { $exe = $Matches[1]; $a = $Matches[2] }
            else { $p = $u -split '\s+',2; $exe = $p[0]; $a = $p[1] }
            if ($a -notmatch '/S|/qn|/quiet') { $a = "$a /S" }
            L "Running: `"$exe`" $a"
            try { Start-Process -FilePath $exe -ArgumentList $a -Wait -WindowStyle Hidden; $done = $true }
            catch { L "Failed: $($_.Exception.Message)" }
        }
      }
}

# 2) known paths
if (-not $done) {
    foreach ($p in 'C:\Program Files (x86)\CentraStage\uninst.exe','C:\Program Files\CentraStage\uninst.exe') {
        if (Test-Path $p) {
            L "Running fallback: $p /S"
            try { Start-Process -FilePath $p -ArgumentList '/S' -Wait -WindowStyle Hidden; $done = $true }
            catch { L "Failed: $($_.Exception.Message)" }
        }
    }
}

Start-Sleep -Seconds 45
if (Get-Service -Name 'CagService' -ErrorAction SilentlyContinue) {
    L 'WARNING: CagService still present - manual removal required.'
} else {
    L 'Datto RMM agent removed.'
}

# clean up after ourselves
try { Unregister-ScheduledTask -TaskName 'Offboard-Remove-DattoRMM' -Confirm:$false -ErrorAction SilentlyContinue; L 'Scheduled task removed.' } catch { }
L '--- Complete ---'
'@

    if ($DryRun) {
        Write-Log "DRY RUN - would stage $removerPath and register task '$taskName'." 'DRY'
        $Summary['Datto RMM removal'] = 'DRY RUN'
    } else {
        try {
            Set-Content -Path $removerPath -Value $remover -Encoding UTF8
            Write-Log "Staged $removerPath"

            $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                          -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$removerPath`""
            $trigger   = New-ScheduledTaskTrigger -AtStartup
            $trigger.Delay = 'PT2M'
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                          -DontStopIfGoingOnBatteries -StartWhenAvailable `
                          -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Principal $principal -Settings $settings `
                -Description 'One-time removal of the Datto RMM agent during offboarding.' `
                -Force | Out-Null

            Write-Log "Scheduled task '$taskName' registered - runs 2 minutes after next boot." 'OK'
            $Summary['Datto RMM removal'] = 'Scheduled for next reboot'
        } catch {
            Write-Log "Could not register scheduled task: $($_.Exception.Message)" 'ERROR'
            $Summary['Datto RMM removal'] = 'FAILED'
        }
    }
} else { $Summary['Datto RMM removal'] = 'Skipped' }

# ---------------------------------------------------------------- summary
Write-Section 'SUMMARY'
foreach ($k in $Summary.Keys) { Write-Log ('{0,-26} : {1}' -f $k, $Summary[$k]) }
Write-Log ''
Write-Log "Log: $LogFile"
if ($credFile) { Write-Log "Credentials: $credFile" }
Write-Log 'NEXT STEP: reboot the machine to trigger Datto RMM removal.'

# Datto RMM job result panel
Write-Output '<-Start Result->'
Write-Output ("OffboardStatus=" + (($Summary.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '))
Write-Output '<-End Result->'

$failed = $Summary.Values | Where-Object { $_ -eq 'FAILED' }
if ($failed) { exit 1 } else { exit 0 }