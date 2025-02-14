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

# Function to process a single item (file or folder) by removing ACEs for the target groups.
function Process-Item {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string[]]$TargetGroups
    )

    Write-Host "Processing item: $Path"
    try {
        $acl = Get-Acl -Path $Path
    }
    catch {
        Write-Warning "Could not get ACL for $Path. Error: $_"
        return
    }
    
    $modified = $false
    foreach ($group in $TargetGroups) {
        $acesToRemove = $acl.Access | Where-Object { $_.IdentityReference.Value -eq $group }
        if ($acesToRemove) {
            foreach ($ace in $acesToRemove) {
                Write-Host "Removing ACE for '$group' on $Path"
                $acl.RemoveAccessRuleSpecific($ace) | Out-Null
                $modified = $true
            }
        }
        else {
            Write-Host "No ACE for '$group' found on $Path"
        }
    }

    if ($modified) {
        try {
            Set-Acl -Path $Path -AclObject $acl
            Write-Host "Updated ACL for $Path"
        }
        catch {
            Write-Warning "Failed to update ACL for $Path. Error: $_"
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

    # If IncludeChildObjects is true and the path is a directory, process all child items recursively.
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
