# Service Path Privilege Escalation

We can use below tools for complete coverage
* PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

# PowerUp
## Get services with unquoted paths and a space in their name.
```powershell
Get-ServiceUnquoted -Verbose
Get-WmiObject -class win32_service | select pathname (wmi command/lists all paths)
```

## Get services where the current user can write to its binary path or change arguments to the binary
```powershell
Get-ModifiableServiceFile -Verbose
```

## Get the services whose configuration current user can modify
```powershell
Get-ModifiableService -Verbose
```

---

## Run all checks from :
#### PowerUp
```powershell
Invoke-Allchecks
```

#### BeRoot is an executable:
```powershell
.\beRoot.exe
```

#### Privesc:
```powershell
Invoke-PrivEsc
```
