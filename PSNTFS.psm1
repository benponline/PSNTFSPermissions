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

function Remove-DirectoryPermission{
    <#
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$Path,
        [parameter(Mandatory = $true)]
        [string]$User
    )

    $dirACL = Get-Acl -Path $Path

    foreach($access in $dirACL.Access){
        if($access.IdentityReference.Value -match $User){
            $dirACL.RemoveAccessRule($access) | Out-Null
        }
    }

    Set-Acl -Path $Path -AclObject $dirACL

    return Get-DirectoryPermission -Path $Path
}