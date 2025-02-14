# Specify the folder you want to update.
$folderPath = "G:\TestACE"  # Change this path as needed

# Define the group and the permission level.
$group = "White-Monkey\Everybody"
$permission = "FullControl"   # Change to "ReadAndExecute", etc., as needed

# Create a FileSystemAccessRule with no inheritance or propagation flags (i.e. an explicit ACE).
$inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
$propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($group, $permission, $inheritanceFlags, $propagationFlags, "Allow")

# Function to add an explicit ACE to a given item.
function Add-ExplicitAce {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemAccessRule]$Ace
    )

    try {
        $acl = Get-Acl -Path $Path
        # Add the new access rule explicitly.
        $acl.AddAccessRule($Ace)
        Set-Acl -Path $Path -AclObject $acl
        Write-Host "Added explicit ACE for '$($Ace.IdentityReference)' on '$Path'"
    }
    catch {
        Write-Warning "Failed to add ACE on '$Path': $_"
    }
}

# Add explicit ACE to the top-level folder.
Add-ExplicitAce -Path $folderPath -Ace $accessRule

# Recursively add explicit ACE for all child objects (files and folders).
Get-ChildItem -Path $folderPath -Recurse -Force | ForEach-Object {
    Add-ExplicitAce -Path $_.FullName -Ace $accessRule
}
