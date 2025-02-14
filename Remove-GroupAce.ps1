[CmdletBinding()]
param(
    # Optional parameter to override the IncludeChildObjects setting from config.json.
    [Parameter(Mandatory=$false)]
    [bool]$IncludeChildObjects
)

# Load configuration from config.json
$script:config = Get-Content -Path "$PSScriptRoot\config.json" | ConvertFrom-Json

# If the -IncludeChildObjects parameter was not passed, use the value from config.json.
if (-not $PSBoundParameters.ContainsKey("IncludeChildObjects")) {
    $IncludeChildObjects = $script:config.IncludeChildObjects
}

# Function to process a single item (file or folder) by removing ACEs for each target group one at a time.
function Process-Item {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string[]]$TargetGroups
    )

    Write-Host "Processing item: $Path"

    foreach ($group in $TargetGroups) {
        # If the group doesn't include a backslash, attempt to resolve its full identity.
        if ($group -notmatch "\\") {
            try {
                $aclInitial = Get-Acl -Path $Path
            }
            catch {
                Write-Warning "Could not get ACL for $Path. Error: $_"
                continue
            }
            $foundAce = $aclInitial.Access | Where-Object { $_.IdentityReference.Value -match "^(.*\\)?$([regex]::Escape($group))$" } | Select-Object -First 1
            if ($foundAce) {
                $resolvedGroup = $foundAce.IdentityReference.Value
                Write-Host "Resolved group for '$group' as '$resolvedGroup' on $Path"
            }
            else {
                # Fallback: use the current user's domain if available, else the local computer name.
                if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) {
                    $resolvedGroup = "$env:USERDOMAIN\$group"
                }
                else {
                    $resolvedGroup = "$env:COMPUTERNAME\$group"
                }
                Write-Host "No ACE found for '$group'; defaulting resolved group to '$resolvedGroup' on $Path"
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
                Write-Warning "Could not get ACL for $Path. Error: $_"
                break
            }
            $ace = $acl.Access | Where-Object { $_.IdentityReference.Value -match $pattern } | Select-Object -First 1
            if (-not $ace) {
                Write-Host "No more ACE for '$group' on $Path"
                break
            }
            Write-Host "Removing ACE for '$group' (pattern: '$pattern') on $Path"
            $acl.RemoveAccessRuleSpecific($ace) | Out-Null
            try {
                Set-Acl -Path $Path -AclObject $acl
                Write-Host "Updated ACL for $Path after removal of '$group'"
            }
            catch {
                Write-Warning "Failed to update ACL for $Path. Error: $_"
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
        Write-Error "TargetGroups not defined in config.json."
        return
    }

    Write-Host "Processing path: $Path with IncludeChildObjects: $IncludeChildObjects"
    
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
foreach ($path in $script:config.Paths) {
    Remove-GroupACE -Path $path -IncludeChildObjects $IncludeChildObjects
}
