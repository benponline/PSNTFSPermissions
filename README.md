# PSNTFS
This module contains functions useful for managing NTFS permissions for share folders and files in a Windows domain. These functions are designed to work well with `Get-ChildItem`. You can pipe directories or files from `Get-ChildItem` to any of these functions to gather or change permissions. Every function is fully documented and works with the `Get-Help` function. 

This module is written for PowerShell Core and tested with Windows 10 machines. I am actively developing this module alongside my work as a system administrator. I use this module every day.

## Installation
1. Download the PSSystemAdministrator.psm1 file.
2. Open the PowerShell modules folder on your computer.
   - For PowerShell Core it is located here: \Documents\PowerShell\Modules
   - For PowerShell 5 it is located here: \Documents\WindowsPowerShell\Modules
3. Create a folder named “PSSystemAdministrator”.
4. Place the PSSystemAdministrator.psm1 file in the new folder.
5. Open your version of PowerShell and run the following command: 
`Set-ExecutionPolicy -ExecutionPolicy RemoteSigned`
6. This will allow PowerShell to read the contents of the module.
7. Open a new PowerShell session and you are good to go.

## Functions
`Disable-ItemInheritance` Disables inheritance on an item.

`Enable-ItemInheritance` Enables inheritance on an item.

`Get-ItemInheritance` Gets the inheritance status of an item.

`Get-ItemPermission` Gets the NTFS permissions from an item.

`Get-UserItemPermission` Gets user permissions for an item.

`Remove-UserItemPermission` Removes NTFS rules from an item that apply to a user.

`Set-UserItemPermission` Sets a permission for a user on an item.