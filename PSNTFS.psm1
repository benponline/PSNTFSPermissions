#Add-UserReadPermission
#Add-UserModifyPermission
#Add-UserFullControlPermission
#Set-UserAsOwner
#Remove-UserReadPermission
#Remove-UserModifyPermission
#Remove-UserFullControlPermission
#Get-UserPermission

#https://blog.netwrix.com/2018/04/18/how-to-manage-file-system-acls-with-powershell-scripts/#How%20to%20disable%20and%20enable%20permission%20inheritance

function Disable-ItemInheritance{
    <#
    .SYNOPSIS
    Disables inheritance on an item.

    .DESCRIPTION
    Disables inheritance on a directory or folder. All current perrmissions are maintained. Current permissions are retained.

    .PARAMETER Path
    Location of the directory or file.

    .INPUTS
    PS Objects with a property name of "Path" or "FullName" for the location of the item.

    .OUTPUTS
    PS Object with the following properties:
        [string]Path                Location of the item
        [bool]HasInheritance        Inheritance status

    .NOTES
    Function is best used when run as an administrator.

    .EXAMPLE
    Disable-ItemInheritance -Path "C:\Directory\SubDirectory"

    Disables the directory "SubDirectory" and sends output to the console confirming the change.

    .EXAMPLE
    "C:\Directory\SubDirectory","C:\Directory\SubDirectory2" | Disable-ItemInheritance
    
    Disables the directories "SubDirectory" and "SubDirectory2" and sends output to the console confirming the changes.

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>

    [CmdletBinding()]
    param(
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Mandatory = $True)]
        [Alias('FullName')]
        [string[]]$Path
    )

    begin{
        $itemPaths = [System.Collections.Generic.List[string]]::new()
        $itemUpdates = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        foreach($p in $Path){
            $itemPaths.Add($p)
        }
    }

    end{
        foreach($itemPath in $itemPaths){

            if(Test-Path -Path $itemPath){
                $directoryACL = Get-ACL -Path $itemPath

                #Disable inheritance and keep current permissions.
                $directoryACL.SetAccessRuleProtection($True, $True)
                Set-Acl -Path $itemPath -AclObject $directoryACL
                $itemUpdates.Add((Get-ItemInheritance -Path $itemPath))
            }else{
                Write-Host "Unable to reach $itemPath."
            }
        }

        return $itemUpdates
    }
}

function Enable-ItemInheritance{
    <#
    .SYNOPSIS
    Enables inheritance on an item.

    .DESCRIPTION
    Enables inheritance on a directory or folder. All current perrmissions are maintained. Current permissions are retained.

    .PARAMETER Path
    Location of the directory or file.

    .INPUTS
    PS Objects with a property name of "Path" or "FullName" for the location of the item.

    .OUTPUTS
    PS Object with the following properties:
        [string]Path                Location of the item
        [bool]HasInheritance        Inheritance status

    .NOTES
    Function is best used when run as an administrator.

    .EXAMPLE
    Enable-ItemInheritance -Path "C:\Directory\SubDirectory"

    Enables the directory "SubDirectory" and sends output to the console confirming the change.

    .EXAMPLE
    "C:\Directory\SubDirectory","C:\Directory\SubDirectory2" | Disable-ItemInheritance
    
    Enables the directories "SubDirectory" and "SubDirectory2" and sends output to the console confirming the changes.

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>

    [CmdletBinding()]
    param(
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Mandatory = $True)]
        [Alias('FullName')]
        [string[]]$Path
    )

    begin{
        $itemPaths = [System.Collections.Generic.List[string]]::new()
        $itemUpdates = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        foreach($p in $Path){
            $itemPaths.Add($p)
        }
    }

    end{
        foreach($itemPath in $itemPaths){

            if(Test-Path -Path $itemPath){
                $itemACL = Get-ACL -Path $itemPath

                #Disable inheritance and keep current permissions.
                $itemACL.SetAccessRuleProtection($False, $True)
                Set-Acl -Path $itemPath -AclObject $itemACL
                $itemUpdates.Add((Get-ItemInheritance -Path $itemPath))
            }else{
                Write-Host "Unable to reach $itemPath."
            }
        }

        return $itemUpdates
    }
}

function Get-ItemInheritance{
    <#
    .SYNOPSIS
    Gets the inheritance status of an item.

    .DESCRIPTION
    Gets the inheritance status of a directory or file.

    .PARAMETER Path
    Location of the directory or file.

    .INPUTS
    PS Objects with a property name of "Path" or "FullName" for the location of the item.

    .OUTPUTS
    PS Object with the following properties:
        [string]Path                Location of the item
        [bool]HasInheritance        Inheritance status

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
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Mandatory = $True)]
        [Alias('FullName')]
        [string[]]$Path
    )

    begin{

    }

    process{}

    end{
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