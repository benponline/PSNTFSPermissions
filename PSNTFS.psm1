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
        [string]FullName                Location of the item
        [bool]HasInheritance        Inheritance status

    .NOTES

    .EXAMPLE
    Get-ItemInheritance -Path "C:\Directory\SubDirectory"

    Gets the inheritance status of "SubDirectory".

    .EXAMPLE
    "C:\Directory\SubDirectory","C:\Directory\SubDirectory2" | Get-ItemInheritance
    
    Gets the inheritance status of the directories "SubDirectory" and "SubDirectory2".

    .EXAMPLE
    Get-ChildItem -Path "C:\Directory" | Get-ItemInheritance
    
    Gets the inheritance status of all the directories and files inside of "C:\Directory".

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
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        foreach($p in $Path){
            $itemPaths.Add($p);
        }
    }

    end{
        foreach($item in $itemPaths){
            if(Test-Path -Path $item){
                $directoryACL = (Get-ACL -Path $item).Access
                $hasInheritance = $false

                foreach($access in $directoryACL){
                    if($access.IsInherited -eq $true){
                        $result = [PSCustomObject]@{
                            Path = $item;
                            HasInheritance = $true
                        }

                        $hasInheritance = $true
                        $results.Add($result)
                        break
                    }
                }

                if($hasInheritance -eq $false){
                    $results.Add([PSCustomObject]@{
                        Path = $item;
                        HasInheritance = $false
                    })
                }

            }else{
                Write-Host "Unable to reach $item."
            }
        }

        return $results
    }
}

function Get-ItemPermission{
    <#
    .SYNOPSIS
    Gets the NTFS permissions from an item.

    .DESCRIPTION
    Gets the NTFS permissions from a directory or file.

    .PARAMETER Path
    Location of the directory or file.

    .INPUTS
    You can pipe PSObjects to this function that contain a property named "Path" or "FullName".

    .OUTPUTS
    PS Object with the following properties:
        [string]Path
        [string]AccessControlType   Allow / Deny
        [string]FileSystemRights    Permissions
        [string]IdentityReference   Account
        [string]InheritanceFlags    
        [bool]IsInherited           True / False
        [string]PropagationFlags    

    .NOTES

    .EXAMPLE
    Get-ItemPermission -Path "C:\Directory\File.txt"

    Gets permissions for "File.txt".

    .EXAMPLE
    Get-ItemPermission -Path "C:\Directory\File.txt","C:\Directory\File2.txt"

    Gets permissions for "File.txt" and "File2.txt".

    .EXAMPLE
    "C:\Directory\File.txt","C:\Directory\File2.txt" | Get-ItemPermission

    Gets permissions for "File.txt" and "File2.txt".

    .EXAMPLE
    Get-ChildItem -Path "C:\Directory" | Get-ItemPermission

    Gets permissions for all directories and files in "C:\Directory".

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>
    
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Mandatory = $true)]
        [Alias('FullName')]
        [string[]]$Path
    )

    begin{
        $itemPaths = [System.Collections.Generic.List[string]]::new()
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        foreach($p in $Path){
            $itemPaths.Add($p)
        }
    }

    end{
        foreach($item in $itemPaths){
            $itemResults = Get-Acl -Path $item | Select-Object -ExpandProperty Access

            foreach($result in $itemResults){
                Add-Member -InputObject $result -MemberType "NoteProperty" -Name "Path" -Value $item
                $results.Add($result)
            }
        }

        return $results
    }
}

function Get-UserPermission{
    <#
    .SYNOPSIS
    Gets user permissions for an item.

    .DESCRIPTION
    Gets a specific user's NTFS permissions for a directory or file. 

    .PARAMETER Path
    Location of the directory or file.

    .PARAMETER SamAccountName
    User account the function is checking for.

    .INPUTS

    .OUTPUTS
    PS Object with the following properties:
        [string]Path
        [string]AccessControlType   Allow / Deny
        [string]FileSystemRights    Permissions
        [string]IdentityReference   Account
        [string]InheritanceFlags    
        [bool]IsInherited           True / False
        [string]PropagationFlags    

    .NOTES

    .EXAMPLE
    Get-ItemUserPermission -Path "C:\Directory\File.txt" -SamAccountName "Thor"

    Returns any permissions for the "Thor" user account on "File.txt".

    .EXAMPLE
    Get-ItemUserPermission -Path "C:\Directory\File.txt","C:\Directory\File2.txt" -SamAccountName "Thor"

    Returns any permissions for the "Thor" user account on "File.txt" and "File2.txt".

    .EXAMPLE
    "C:\Directory\File.txt","C:\Directory\File2.txt" | Get-ItemUserPermission -SamAccountName "Thor"

    Returns any permissions for the "Thor" user account on "File.txt" and "File2.txt".

    .LINK
    By Ben Peterson
    linkedin.com/in/benponline
    github.com/benponline
    twitter.com/benponline
    paypal.me/teknically
    #>
    
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Mandatory = $true)]
        [Alias('FullName')]
        [string[]]$Path,

        [parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    begin{
        $itemPaths = [System.Collections.Generic.List[string]]::new()
    }

    Process{
        foreach ($p in $Path) {
            $itemPaths.Add($p);
        }
    }

    end{
        $itemPathsArray = [string[]]::new($itemPaths.Count)

        $counter = 0
        foreach ($p in $itemPaths) {
            $itemPathsArray[$counter] = $p
            $counter++
        }

        $userPermissions = Get-ItemPermission -Path $itemPathsArray | Where-Object -Property IdentityReference -Match $SamAccountName

        return $userPermissions
    }
}

###
function Remove-UserPermission{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Path

    .PARAMETER SamAccountName

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
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Mandatory = $True)]
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

function Set-UserPermission{
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
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Mandatory = $True)]
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