#Add-UserReadPermission
#Add-UserModifyPermission
#Add-UserFullControlPermission
#Add-UserAsOwner
#Remove-UserReadPermission
#Remove-UserModifyPermission
#Remove-UserFullControlPermission
#Get-UserPermission

function Disable-FolderInheritance{
    <#
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$directoryPath
    )

    if(Test-Path -Path $directoryPath){
        $directoryACL = Get-ACL -Path $directoryPath

        #Disable inheritance and keep current permissions.
        $directoryACL.SetAccessRuleProtection($True, $True)
        
        Set-Acl -Path $directoryPath -AclObject $directoryACL
    }else{
        Write-Host "Unable to reach $directoryPath."
    }

}