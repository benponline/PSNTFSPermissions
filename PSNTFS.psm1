#Add-UserReadPermission
#Add-UserModifyPermission
#Add-UserFullControlPermission
#Add-UserAsOwner
#Remove-UserReadPermission
#Remove-UserModifyPermission
#Remove-UserFullControlPermission
#Get-UserPermission

function Disable-DirectoryInheritance{
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

function Get-DirectoryInheritance{
    <#
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

function Get-DirectoryPermission{
    <#
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path
    )

    return Get-Acl -Path $Path | Select-Object -ExpandProperty Access
}

function Get-DirectoryUserPermission{
    <#
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
function Remove-DirectoryUserPermission{
    <#
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

function Set-DirectoryUserPermission{
    <#
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path,

        [parameter(Mandatory = $true)]
        [string]$SamAccountName,
        
        [parameter()]
        [Switch] $FullControl,
        
        [parameter()]
        [Switch] $Modify,
        
        [parameter()]
        [Switch] $ReadAndExecute,

        [parameter()]
        [Switch] $ListContents
    )
    ###
    $dirACL = Get-Acl -Path $Path

    foreach($access in $dirACL.Access){
        if($access.IdentityReference.Value -match $SamAccountName){
            $dirACL.RemoveAccessRule($access) | Out-Null
        }
    }

    Set-Acl -Path $Path -AclObject $dirACL

    return Get-DirectoryPermission -Path $Path
}