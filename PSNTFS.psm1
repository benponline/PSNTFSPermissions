#Add-UserReadPermission
#Add-UserModifyPermission
#Add-UserFullControlPermission
#Set-UserAsOwner
#Remove-UserReadPermission
#Remove-UserModifyPermission
#Remove-UserFullControlPermission
#Get-UserPermission

function Disable-ItemInheritance{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Name

    .INPUTS

    .OUTPUTS

    .NOTES

    .EXAMPLE 

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path
    )

    if(Test-Path -Path $Path){
        $directoryACL = Get-ACL -Path $Path

        #Disable inheritance and keep current permissions.
        $directoryACL.SetAccessRuleProtection($True, $True)
        
        Set-Acl -Path $Path -AclObject $directoryACL
    }else{
        Write-Host "Unable to reach $Path."
    }
}

function Get-ItemInheritance{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Name

    .INPUTS

    .OUTPUTS

    .NOTES

    .EXAMPLE 

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path
    )

    if(Test-Path -Path $Path){
        $directoryACL = (Get-ACL -Path $Path).Access

        foreach($access in $directoryACL){
            if($access.IsInherited -eq $true){
                $result = [PSCustomObject]@{
                    Path = $Path;
                    HasInheritance = $true
                }

                return $result 
            }
        }

        $result = [PSCustomObject]@{
            Path = $Path;
            HasInheritance = $false
        }

        return $result
    }else{
        Write-Host "Unable to reach $Path."
    }
}

function Get-ItemPermission{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Name

    .INPUTS

    .OUTPUTS

    .NOTES

    .EXAMPLE 

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path
    )

    return Get-Acl -Path $Path | Select-Object -ExpandProperty Access
}

function Get-ItemUserPermission{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Name

    .INPUTS

    .OUTPUTS

    .NOTES

    .EXAMPLE 

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path,
        [parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    return Get-DirectoryPermission -Path $Path | Where-Object -Property IdentityReference -Match $SamAccountName
}

##
function Remove-ItemUserPermission{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Name

    .INPUTS

    .OUTPUTS

    .NOTES

    .EXAMPLE 

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path,
        [parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    $dirACL = Get-Acl -Path $Path

    foreach($access in $dirACL.Access){
        if($access.IdentityReference.Value -match $SamAccountName){
            $dirACL.RemoveAccessRule($access) | Out-Null
        }
    }

    Set-Acl -Path $Path -AclObject $dirACL

    return Get-DirectoryPermission -Path $Path
}

function Set-ItemUserPermission{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Name

    .INPUTS

    .OUTPUTS

    .NOTES

    .EXAMPLE 

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    Developed with help from https://adamtheautomator.com/how-to-manage-ntfs-permissions-with-powershell/ 
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path,

        [parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [parameter(Mandatory = $true)]
        [ValidateSet("FullControl","Modify","ReadAndExecute","Read","Write")]
        [string]$Permission,

        [parameter(Mandatory = $true)]
        [ValidateSet("Allow","Deny")]
        [string]$Access
    )

    $acl = Get-Acl -Path $Path
    $aclRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SamAccountName,$Permission,"ContainerInherit, ObjectInherit", "None", $Access)
    $acl.SetAccessRule($aclRule)
    Set-Acl -Path $Path -AclObject $acl

    return Get-ItemPermission -Path $Path
}