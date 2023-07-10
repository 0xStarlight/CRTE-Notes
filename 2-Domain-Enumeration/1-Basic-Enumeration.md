# PowerView Enumeration
## Get current domain
```powershell
Get-NetDomain
```

## Get object of another domain
```poweshell
Get-NetDomain -Domain moneycorp.local
```

## Get domain SID for the current domain
```powerhshell
Get-DomainSID
```

## Get domain policy for the current domain
```powershell
Get-DomainPolicy
(Get-DomainPolicy)."system access"
```

## Get domain policy for another domain
```powershell
(Get-DomainPolicy -domain moneycorp.local)."system access"
(Get-DomainPolicy -domain moneycorp.local)."kerberos policy"
(Get-DomainPolicy -domain moneycorp.local)."Privilege Rights"
# OR
(Get-DomainPolicy)."KerberosPolicy" #Kerberos tickets info(MaxServiceAge)
(Get-DomainPolicy)."SystemAccess" #Password policy
(Get-DomainPolicy).PrivilegeRights #Check your privileges
```

## Get domain controllers for the current domain
```powershell
Get-NetDomainController
```

## Get domain controllers for another domain
```powershell
Get-NetDomainController -Domain moneycorp.local
```

## Get a list of users in the current domain
```powershell
Get-NetUser
Get-NetUser -Username student1
```

## Get list of all properties for users in the current domain
```powershell
Get-UserProperty
Get-UserProperty -Properties pwdlastset,logoncount,badpwdcount
Get-UserProperty -Properties logoncount
Get-UserProperty -Properties badpwdcount
```

## Search for a particular string in a user's attributes
```powershell
Find-UserField -SearchField Description -SearchTerm "built"
```

## Get a list of computers in the current domain
```powershell
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
```


## Get all the groups in the current domain
```powershell
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData
Get-NetComputer -Domain
```

## Get all groups containing the word "admin" in group name
```powershell
Get-NetGroup *admin*
Get-NetGroup -GroupName *admin*
Get-NetGroup *admin* -FullData
Get-NetGroup -GroupName *admin* -Doamin moneycorp.local
```

## Get all the members of the Domain Admins group
```powershell
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
#test the below command
#Get-NetGroupMember -GroupName "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members
```


## Get the group membership for a user
```powershell
Get-NetGroup -UserName "student1"
```

## List all the local groups on a machine (needs administrator privs on non-dc machines) 
```powershell
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
```

## Get members of all the local groups on a machine (needs administrator privs on non-dc machines)
```powershell
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```

## Get actively logged users on a computer (needs local admin rights on the target)
```powershell
Get-NetLoggedon -ComputerName dcorp-dc.dollarcorp.moneycorp.local 
```

## Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
```powershell
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local 
```
 
## Get the last logged user on a computer (needs administrative rights and remote registry on the target)
```powershell
Get-LastLoggedon -ComputerName <servername>
```

## Find shares on hosts in current domain.
```powershell
Invoke-ShareFinder -Verbose
```

## Find sensitive files on computers in the domain
```powershell
Invoke-FileFinder -Verbose
```

## Get all fileservers of the domain
```powershell
Get-NetFileServer
```