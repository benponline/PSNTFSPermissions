<#
This module is meant to be used in a Windows Domain by a domain administrator.

By:
Ben Peterson
linkedin.com/in/benponline
github.com/benponline
twitter.com/benponline
paypal.me/teknically
#>

function Disable-ItemInheritance{
    <#
    .SYNOPSIS
    Disables inheritance on an item.

    .DESCRIPTION
    Disables inheritance on a directory or folder. All current permissions are maintained. Current permissions are retained. Returns PS Objects with properties confirming that inheritance has been disabled on the item.

    .PARAMETER Path
    Location of the directory or file.

    .INPUTS
    PS Objects with one of the following properties:
        [string]Path                Location of the item
        [string]FullName            Location of the item

    .OUTPUTS
    PS Object with the following properties:
        [string]FullName            Location of the item
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
        [Alias('Path')]
        [string]$FullName
    )

    begin{
        $fullNames = [System.Collections.Generic.List[string]]::new()
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        $fullNames.Add($FullName)
    }

    end{
        foreach($fn in $fullNames){

            if(Test-Path -Path $fn){
                $directoryACL = Get-ACL -Path $fn

                #Disable inheritance and keeps current permissions.
                $directoryACL.SetAccessRuleProtection($True, $True)
                Set-Acl -Path $fn -AclObject $directoryACL
                $results.Add((Get-ItemInheritance -Path $fn))
            }else{
                Write-Host "Unable to reach $fn."
            }
        }

        return $results
    }
}

function Enable-ItemInheritance{
    <#
    .SYNOPSIS
    Enables inheritance on an item.

    .DESCRIPTION
    Enables inheritance on a directory or folder. All current perrmissions are maintained. Current permissions are retained. Returns PS Objects with properties confirming that inheritance has been enabled on the item.

    .PARAMETER Path
    Location of the directory or file.

    .INPUTS
    PS Objects with one of the following properties:
        [string]Path                Location of the item
        [string]FullName            Location of the item

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
        [Alias('Path')]
        [string[]]$FullName
    )

    begin{
        $fullNames = [System.Collections.Generic.List[string]]::new()
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        $fullNames.Add($FullName)
    }

    end{
        foreach($fn in $fullNames){
            if(Test-Path -Path $fn){
                $itemACL = Get-ACL -Path $fn

                #Disable inheritance and keep current permissions.
                $itemACL.SetAccessRuleProtection($False, $True)
                Set-Acl -Path $fn -AclObject $itemACL
                $results.Add((Get-ItemInheritance -Path $fn))
            }else{
                Write-Host "Unable to reach $fn."
            }
        }

        return $results
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
    PS Objects with one of the following properties:
        [string]Path                Location of the item
        [string]FullName            Location of the item

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
        [alias('Path')]
        [string[]]$FullName
    )

    begin{
        $fullNames = [System.Collections.Generic.List[string]]::new()
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        $fullNames.Add($FullName);
    }

    end{
        foreach($fn in $fullNames){
            if(Test-Path -Path $fn){
                $directoryACL = (Get-ACL -Path $fn).Access
                $hasInheritance = $false

                foreach($access in $directoryACL){
                    if($access.IsInherited -eq $True){
                        $result = [PSCustomObject]@{
                            FullName = $fn;
                            HasInheritance = $True
                        }

                        $hasInheritance = $True
                        $results.Add($result)
                        break
                    }
                }

                if($hasInheritance -eq $false){
                    $results.Add([PSCustomObject]@{
                        FullName = $fn;
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
    PS Objects with one of the following properties:
        [string]Path                Location of the item
        [string]FullName            Location of the item

    .OUTPUTS
    PS Object with the following properties:
        [string]FullName
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
        [Alias('Path')]
        [string[]]$FullName
    )

    begin{
        $fullNames = [System.Collections.Generic.List[string]]::new()
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        $fullNames.Add($FullName)
    }

    end{
        foreach($fn in $fullNames){
            $itemResults = Get-Acl -Path $fn | Select-Object -ExpandProperty Access

            foreach($result in $itemResults){
                Add-Member -InputObject $result -MemberType "NoteProperty" -Name "FullName" -Value $fn
                $results.Add($result)
            }
        }

        return $results
    }
}

function Get-UserItemPermission{
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
    PS Objects with one of the following properties:
        [string]Path                Location of the item
        [string]FullName            Location of the item

    .OUTPUTS
    PS Object with the following properties:
        [string]FullName
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
        [Alias('Path')]
        [string]$FullName,

        [parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    begin{
        $fullNames = [System.Collections.Generic.List[string]]::new()
        $itemPermissions = [System.Collections.Generic.List[psobject]]::new()
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    Process{
        $fullNames.Add($FullName)
    }

    end{
        $itemPermissions = $fullNames | Get-ItemPermission
        
        foreach($item in $itemPermissions){
            $identityReferenceRaw = $item.IdentityReference -as [string]
            
            if($identityReferenceRaw.contains("\") ){
                $identityReference = $identityReferenceRaw.split("\")[-1]
                
                if($identityReference -eq $SamAccountName){
                    $results.Add($item)
                }
            }
        }

        return $results
    }
}

function Remove-UserItemPermission{
    <#
    .SYNOPSIS
    Removes NTFS rules from an item that apply to a user.

    .DESCRIPTION
    Removes NTFS rules from a directory or file that apply to a specific user. Returns PS Objects with properties confirming the removal of user permission rules.

    .PARAMETER FullName
    Full path the directory or file.

    .PARAMETER SamAccountName
    The user that will be removed by the function.

    .INPUTS
    PS Objects with one of the following properties:
        [string]Path                Location of the item
        [string]FullName            Location of the item

    .OUTPUTS
    PS Objects with the following properties:
        [string]FullName
        [System.Security.AccessControl.AccessControlType]AccessControlType
        [System.Security.AccessControl.FileSystemRights]FileSystemRights
        [System.Security.Principal.IdentityReference]IdentityReference
        [System.Security.AccessControl.InheritanceFlags]InheritanceFlags
        [bool]IsInherited
        [System.Security.AccessControl.PropagationFlags]PropagationFlags 

    .NOTES

    .EXAMPLE 
    Remove-UserItemPermission -FullName "C:\Folder\Doc.txt" -SamAccountName "Carl"

    This removes all NTFS rules from "Doc.txt" and apply to the user "Carl".

    .EXAMPLE
    "C:\Folder\Doc.txt" | Remove-UserItemPermission -SamAccountName "Carl"

    This removes all NTFS rules from "Doc.txt" and apply to the user "Carl".

    .EXAMPLE
    Get-ChildItem -Path "C:\Folder" | Remove-UserItemPermission -SamAccountName "Carl"

    This removes all NTFS rules from all directories and files in the "Folder" directory that apply to the user "Carl".

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
        [alias("Path")]
        [string]$FullName,

        [parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    begin{
        $fullNames = [System.Collections.Generic.List[string]]::new()
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        $fullNames.Add($FullName)
    }

    end{
        foreach($fn in $fullNames){
            $dirACL = Get-Acl -Path $fn

            foreach($access in $dirACL.Access){
                if($access.IdentityReference.Value -match $SamAccountName){
                    $dirACL.RemoveAccessRule($access) | Out-Null
                }
            }

            Set-Acl -Path $fn -AclObject $dirACL
        }

        foreach($fn in $fullNames){
            $permissions = Get-ItemPermission -FullName $fn

            foreach($permission in $permissions){
                $results.Add($permission)
            }
        }

        return $results
    }
}

function Set-UserItemPermission{
    <#
    .SYNOPSIS
    Sets a permission for a user on an item.

    .DESCRIPTION
    Sets an NTFS rule for a user on a directory or file. Returns PS Objects confirming the added rule. 

    .PARAMETER FullName
    Full path and name of the directory or file.

    .PARAMETER SamAccountName
    User account.

    .PARAMETER Permission
    The type of permission that will be included in the rule. Valid options are:
        FullControl
        Modify
        ReadAndExecute
        Read
        Write

    .PARAMETER Access
    The type of access that the rule will give. Valid options are:
        Allow
        Deny

    .INPUTS
    PS Objects with one of the following properties:
        [string]Path                Location of the item
        [string]FullName            Location of the item

    .OUTPUTS
    PS Object with the following properties:
        [string]FullName
        [string]AccessControlType   Allow / Deny
        [string]FileSystemRights    Permissions
        [string]IdentityReference   Account
        [string]InheritanceFlags    
        [bool]IsInherited           True / False
        [string]PropagationFlags    

    .NOTES

    .EXAMPLE
    Set-UserItemPermission -FullName "\\fileserver\Folder" -SamAccountName "Thor" -Permission "modify" -Access "allow"

    Addes an NTFS rule giving "Thor" modify permissions for the "Folder" directory.

    .EXAMPLE
    "\\fileserver\Folder","\\fileserver\FolderA" | Set-UserItemPermission -SamAccountName "Thor" -Permission "modify" -Access "allow"

    Addes an NTFS rules giving "Thor" modify permissions for the "Folder" and "FolderA" directories.

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
        [alias("Path")]
        [string]$FullName,

        [parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [parameter(Mandatory = $true)]
        [ValidateSet("FullControl","Modify","ReadAndExecute","ListFolderContents","Read","Write")]
        [string]$Permission,

        [parameter(Mandatory = $true)]
        [ValidateSet("Allow","Deny")]
        [string]$Access
    )

    begin{
        $fullNames = [System.Collections.Generic.List[string]]::new()
        $results = [System.Collections.Generic.List[psobject]]::new()
    }

    process{
        $fullNames.Add($FullName)
    }

    end{
        foreach($fn in $fullNames){
            $acl = Get-Acl -Path $fn
            $aclRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SamAccountName,$Permission,"ContainerInherit, ObjectInherit", "None", $Access)
            $acl.SetAccessRule($aclRule)
            Set-Acl -Path $fn -AclObject $acl
        }

        foreach($fn in $fullNames){
            $updatedPermissions = Get-UserItemPermission -Path $fn -SamAccountName $SamAccountName

            foreach($up in $updatedPermissions){
                $results.Add($up)
            }
        }
    
        return $results
    }
}