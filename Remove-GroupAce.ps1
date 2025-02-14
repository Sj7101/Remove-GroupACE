[CmdletBinding()]
param(
    # Optional parameter to override the IncludeChildObjects setting from config.json.
    [Parameter(Mandatory=$false)]
    [bool]$IncludeChildObjects
)

# Define the log file (placed in the same folder as the script)
$LogFile = "$PSScriptRoot\Remove-AceLog.txt"

# Logging function: writes log entries in the format [YYYY-MM-DD][HH:mm:ss][ERR/INF/SYS][Message]
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("ERR", "INF", "SYS")]
        [string]$Level,
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    $date = Get-Date -Format "yyyy-MM-dd"
    $time = (Get-Date -Format "HH:mm:ss")
    $line = "[$date][$time][$Level][$Message]"
    Add-Content -Path $LogFile -Value $line
}

Write-Log "SYS" "Loading configuration from config.json"
$script:config = Get-Content -Path "$PSScriptRoot\config.json" | ConvertFrom-Json

if (-not $PSBoundParameters.ContainsKey("IncludeChildObjects")) {
    Write-Log "SYS" "Including all Child Objects"
    $IncludeChildObjects = $script:config.IncludeChildObjects
}else{
    Write-Log "SYS" "Skipping all Child Objects"
}

# Function to process a single item (file or folder) by removing ACEs for each target group one at a time.
function Process-Item {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string[]]$TargetGroups
    )

    Write-Log "INF" "Processing item: $Path"

    foreach ($group in $TargetGroups) {
        # If the group doesn't include a backslash, attempt to resolve its full identity.
        if ($group -notmatch "\\") {
            try {
                $aclInitial = Get-Acl -Path $Path
            }
            catch {
                Write-Log "ERR" "Could not get ACL for $Path. Error: $_"
                continue
            }
            $foundAce = $aclInitial.Access | Where-Object { $_.IdentityReference.Value -match "^(.*\\)?$([regex]::Escape($group))$" } | Select-Object -First 1
            if ($foundAce) {
                $resolvedGroup = $foundAce.IdentityReference.Value
                Write-Log "INF" "Resolved group for '$group' as '$resolvedGroup' on $Path"
            }
            else {
                # Fallback: use the current user's domain if available and different from $env:COMPUTERNAME, otherwise $env:COMPUTERNAME.
                if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) {
                    $resolvedGroup = "$env:USERDOMAIN\$group"
                }
                else {
                    $resolvedGroup = "$env:COMPUTERNAME\$group"
                }
                Write-Log "INF" "No matching ACE found; defaulting resolved group to '$resolvedGroup' on $Path"
            }
            $pattern = "^(.*\\)?{0}$" -f [regex]::Escape($resolvedGroup)
        }
        else {
            $pattern = "^(.*\\)?{0}$" -f [regex]::Escape($group)
        }

        # Remove matching ACEs one at a time.
        while ($true) {
            try {
                $acl = Get-Acl -Path $Path
            }
            catch {
                Write-Log "ERR" "Could not get ACL for $Path. Error: $_"
                break
            }
            $ace = $acl.Access | Where-Object { $_.IdentityReference.Value -match $pattern } | Select-Object -First 1
            if (-not $ace) {
                Write-Log "INF" "No more ACE for '$group' on $Path"
                break
            }
            if ($ace.IsInherited) {
                Write-Log "INF" "No more inherited ACE for '$group' on $Path"
                break
            }
            Write-Log "INF" "Removing explicit ACE for '$group' (pattern: '$pattern') on $Path"
            $acl.RemoveAccessRuleSpecific($ace) | Out-Null
            try {
                Set-Acl -Path $Path -AclObject $acl
                Write-Log "INF" "Updated ACL for $Path after removal of '$group'"
            }
            catch {
                Write-Log "ERR" "Failed to update ACL for $Path. Error: $_"
                break
            }
        }
    }
}

# Function to remove ACEs for all target groups from a given path.
function Remove-GroupACE {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [bool]$IncludeChildObjects
    )

    $targetGroups = $script:config.TargetGroups
    if (-not $targetGroups -or $targetGroups.Count -eq 0) {
        Write-Log "ERR" "TargetGroups not defined in config.json."
        return
    }

    Write-Log "INF" "Processing path: $Path with IncludeChildObjects: $IncludeChildObjects"
    
    # Process the top-level item.
    Process-Item -Path $Path -TargetGroups $targetGroups

    # If IncludeChildObjects is true and the path is a container, process all child items recursively.
    if ($IncludeChildObjects -and (Test-Path $Path -PathType Container)) {
        $childItems = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($item in $childItems) {
            Process-Item -Path $item.FullName -TargetGroups $targetGroups
        }
    }
}

# Main execution: Loop through each path specified in the config file.
Write-Log "SYS" "=========================================================================================="

foreach ($path in $script:config.Paths) {
    Remove-GroupACE -Path $path -IncludeChildObjects $IncludeChildObjects
}

Write-Log "SYS" "Removal job completed."
Write-Log "SYS" "=========================================================================================="
