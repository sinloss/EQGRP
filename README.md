# PREFACE
This is the merged version of two repos of [EQGRP_Lost_in_Translation](https://github.com/x0rz/EQGRP_Lost_in_Translation) and [EQGRP](https://github.com/x0rz/EQGRP)   
It's originally stolen from Equation Group (Which is alleged to be an unit of NSA) by [ShadowBrokers](https://steemit.com/@theshadowbrokers)

# EQGRP_Lost_in_Translation
https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation

## Exploits

- **EARLYSHOVEL** RedHat 7.0 - 7.1 Sendmail 8.11.x exploit 
- **EBBISLAND (EBBSHAVE)** root RCE via RPC XDR overflow in Solaris 6, 7, 8, 9 & 10 (possibly newer) both SPARC and x86.
- **ECHOWRECKER** remote Samba 3.0.x Linux exploit. 
- **EASYBEE** appears to be an MDaemon email server vulnerability
- **EASYFUN** EasyFun 2.2.0 Exploit for WDaemon / IIS MDaemon/WorldClient pre 9.5.6
- **EASYPI** is an IBM Lotus Notes exploit  that gets detected as Stuxnet 
- **EWOKFRENZY** is an exploit for IBM Lotus Domino 6.5.4 & 7.0.2
- **EXPLODINGCAN** is an IIS 6.0 exploit that creates a remote backdoor
- **ETERNALROMANCE** is a SMB1 exploit over TCP port 445 which targets XP, 2003, Vista, 7, Windows 8, 2008, 2008 R2, and gives SYSTEM privileges (MS17-010)
- **EDUCATEDSCHOLAR** is a SMB exploit (MS09-050)
- **EMERALDTHREAD** is a SMB exploit for Windows XP and Server 2003 (MS10-061)
- **EMPHASISMINE** is a remote IMAP exploit for IBM Lotus Domino 6.6.4 to 8.5.2
- **ENGLISHMANSDENTIST** sets Outlook Exchange WebAccess rules to trigger executable code on the client's side to send an email to other users
- **EPICHERO** 0-day exploit (RCE) for Avaya Call Server
- **ERRATICGOPHER** is a SMBv1 exploit targeting Windows XP and Server 2003 
- **ETERNALSYNERGY** is a SMBv3 remote code execution flaw  for Windows 8 and Server 2012 SP0 (MS17-010)
- **ETERNALBLUE is** a SMBv2 exploit for Windows 7 SP1 (MS17-010)
- **ETERNALCHAMPION** is a SMBv1 exploit
- **ESKIMOROLL** is a Kerberos exploit targeting 2000, 2003, 2008 and 2008 R2 domain controllers
- **ESTEEMAUDIT** is an RDP exploit and backdoor for Windows Server 2003
- **ECLIPSEDWING** is an RCE exploit for the Server service in Windows Server 2008 and later (MS08-067)
- **ETRE** is an exploit for IMail 8.10 to 8.22 
- **ETCETERABLUE** is an exploit for IMail 7.04 to 8.05
- **FUZZBUNCH** is an exploit framework, similar to MetaSploit
- **ODDJOB** is an implant builder and C&C server that can deliver exploits for Windows 2000 and later, also not detected by any AV vendors 
- **EXPIREDPAYCHECK** IIS6 exploit
- **EAGERLEVER** NBT/SMB exploit for Windows NT4.0, 2000, XP SP1 & SP2, 2003 SP1 & Base Release
- **EASYFUN** WordClient / IIS6.0 exploit
- **ESSAYKEYNOTE** 
- **EVADEFRED**


## Utilities

- **PASSFREELY** utility which "Bypasses authentication for Oracle servers"
- **SMBTOUCH** check if the target is vulnerable to samba exploits like ETERNALSYNERGY, ETERNALBLUE, ETERNALROMANCE 
- **ERRATICGOPHERTOUCH**  Check if the target is running some RPC
- **IISTOUCH** check if the running IIS version is vulnerable
- **RPCOUTCH** get info about windows via RPC
- **DOPU** used to connect to machines exploited by ETERNALCHAMPIONS
- **NAMEDPIPETOUCH** Utility to test for a predefined list of named pipes, mostly AV detection. User can add checks for custom named pipes.

# EQGRP
- Original file: https://mega.nz/#!zEAU1AQL!oWJ63n-D6lCuCQ4AY0Cv_405hX8kn7MEsa1iLH5UjKU
- Passphrase: `CrDj"(;Va.*NdlnzB9M?@K2)#>deB7mN` (as disclosed by the ShadowBrokers, [source](https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1))
- This summary is provided by the community: complaints/credits to `jvoisin` @ `dustri.org` and [@x0rz](https://www.twitter.com/x0rz)

⚠️ Some binaries may be picked up by your antivirus

Nested Tar archives have been uncompressed in the [archive_files](/archive_files) folder.

## Content
## Unknown
- **JACKLADDER** 
- **DAMPCROWD**
- **ELDESTMYDLE**
- **SUAVEEYEFUL**
- **WATCHER**
- **YELLOWSPIRIT**

## Misc
- **DITTLELIGHT (HIDELIGHT)** unhide **NOPEN** window to run unix oracle db scripts
- **DUL** shellcode packer
- **egg_timer** execution delayer (equivalent to `at`)
- **ewok** [snmpwalk](http://www.net-snmp.org/docs/man/snmpwalk.html)-like?
- **gr** Web crontab manager? wtf. NSA are webscale dude
- **jackladderhelper** simple port binder
- **magicjack** [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) implementation in Perl 
- **PORKSERVER** inetd-based server for the **PORK** implant
- **ri** equivalent to `rpcinfo`
- **uX_local** Micro X server, likely for remote management
- **ITIME** Change Date/Time of a last change on a file of an unix filesystem

## Remote Code Execution 
## Solaris
- **CATFLAP** Solaris 7/8/9 (SPARC and Intel) RCE (for a [__LOT__]( https://twitter.com/hackerfantastic/status/850799265723056128 ) of versions)
- **EASYSTREET**/**CMSEX** and **cmsd** Solaris `rpc.cmsd` remote root
- **EBBISLAND**/**ELVISCICADA**/**snmpXdmid** and **frown**: `CVE-2001-0236`, Solaris 2.6-2.9 - snmpXdmid Buffer Overflow
- **sneer**: *mibissa* (Sun snmpd) RCE, with *DWARF* symbols :D
- **dtspcdx_sparc** dtspcd RCE for SunOS 5. -5.8. what a useless exploit
- **TOOLTALK** DEC, IRIX, or Sol2.6 or earlier Tooltalk buffer overflow RCE
- **VIOLENTSPIRIT** RCE for ttsession daemon in CDE on Solaris 2.6-2.9 on SPARC and x86
- **EBBISLAND**  RCE Solaris 2.6 -> 2.10 Inject shellcode in vulnerable rpc service

### Netscape Server
- **xp_ns-httpd** NetScape Server RCE
- **nsent** RCE for NetScape Enterprise server 4.1 for Solaris
- **eggbasket** another NetScape Enterprise RCE, this time version `3.5`, likely SPARC only

### FTP servers
- **EE** proftpd 1.2.8 RCE, for RHL 7.3+/Linux, `CVE-2011-4130`? another reason not to use proftpd
- **wuftpd** likely `CVE-2001-0550`

### Web 
- **ESMARKCONANT** exploits phpBB remote command execution (<[2.0.11](https://www.phpbb.com/community/viewtopic.php?t=240636)) `CVE-2004-1315`
- **ELIDESKEW** Public known vulnerablity in [SquirrelMail](https://squirrelmail.org/) versions 1.4.0 - 1.4.7
- **ELITEHAMMER** Runs against RedFlag Webmail 4, yields user `nobody`
- **ENVISIONCOLLISION** RCE for phpBB (derivative)
- **EPICHERO** RCE for Avaya Media Server
- **COTTONAXE** RCE to retrieve log and information on LiteSpeed Web Server

### Misc
- **calserver** spooler RPC based RCE
- **EARLYSHOVEL** RCE RHL7 using sendmail  ` CVE-2003-0681 ` ` CVE-2003-0694 `
- **ECHOWRECKER**/**sambal**: samba 2.2 and 3.0.2a - 3.0.12-5 RCE (with *DWARF* symbols), for FreeBSD, OpenBSD 3.1, OpenBSD 3.2 (with a non-executable stack, zomg), and Linux. Likely `CVE-2003-0201`. There is also a Solaris version
- **ELECTRICSLIDE** RCE (heap-overflow) in [Squid](http://www.squid-cache.org/), with a chinese-looking vector
- **EMBERSNOUT** a remote exploit against Red Hat 9.0's httpd-2.0.40-21
- **ENGAGENAUGHTY**/**apache-ssl-linux** Apache2 mod-ssl RCE (2008), SSLv2
- **ENTERSEED** Postfix RCE, for 2.0.8 - 2.1.5
- **ERRGENTLE**/**xp-exim-3-remote-linux** Exim remote root, likely `CVE-2001-0690`, Exim 3.22 - 3.35
- **EXPOSITTRAG** exploit pcnfsd version 2.x
- **extinctspinash**: `Chili!Soft ASP` stuff RCE? and *Cobalt RaQ* too?
- **KWIKEMART** (**km** binary) RCE for SSH1 padding crc32 thingy (https://packetstormsecurity.com/files/24347/ssh1.crc32.txt.html)
- **prout** (ab)use of `pcnfs` RPC program (version 2 only) (1999)
- **slugger**: various printers RCE, looks like `CVE-1999-0078`
- **statdx** Redhat Linux 6.0/6.1/6.2 rpc.statd remote root exploit (IA32)
- **telex** Telnetd RCE for RHL?  `CVE-1999-0192`?
- **toffeehammer** RCE for `cgiecho` part of `cgimail`, exploits fprintf
- **VS-VIOLET** Solaris 2.6 - 2.9, something related to [XDMCP](https://en.wikipedia.org/wiki/X_display_manager_(program_type)#X_Display_Manager_Control_Protocol)
- **SKIMCOUNTRY** Steal mobile phone log data
- **SLYHERETIC_CHECKS** Check if a target is ready for **SLYHERETIC** (not included)
- **EMPTYBOWL** RCE for MailCenter Gateway (mcgate) - an application that comes with Asia Info Message Center mailserver; buffer overflow allows a string passed to popen() call to be controlled by an attacker; arbitraty cmd execute known to work only for AIMC Version 2.9.5.1
- **CURSEHAPPY** Parser of CDR (Call Detail Records) (siemens, alcatel, other containing isb hki lhr files) probably upgrade of ORLEANSTRIDE
- **ORLEANSTRIDE** Parser of CDR (Call Detail Records)

## Anti-forensic
- **toast**: `wtmps` editor/manipulator/querier
- **pcleans**: `pacctl` manipulator/cleaner
- **DIZZYTACHOMETER**: Alters RPM database when system file is changed so that RPM (>4.1) verify doesn't complain 
- **DUBMOAT** Manipulate utmp
- **scrubhands** post-op cleanup tool?
- **Auditcleaner** cleans up `audit.log`

## Control
## Iting HP-UX, Linux, SunOS
- **FUNNELOUT**: database-based web-backdoor for `vbulletin`
- **hi** UNIX bind shell
- **jackpop** bind shell for SPARC
- **NOPEN** Backdoor? A RAT or post-exploitation shell consisting of a client and a server that encrypts data using RC6 [source](http://electrospaces.blogspot.nl/p/nsas-tao-division-codewords.html)** SunOS5.8
- **SAMPLEMAN / ROUTER TOUCH** Clearly hits Cisco via some sort of redirection via a tool on port 2323... (thanks to @cynicalsecurity)
- **SECONDDATE** Implant for Linux/FreeBSD/Solaris/JunOS
- **SHENTYSDELIGHT** Linux keylogger
- **SIDETRACK** implant used for **PITCHIMPAIR**
- **SIFT** Implant for Solaris/Linux/FreeBSD
- **SLYHERETIC** SLYHERETIC is a light-weight implant for AIX 5.1:-5.2 Uses Hide-in-Plain-Sight techniques to provide stealth.
- **STRIFEWORLD**: Network-monitoring for UNIX, needs to be launched as root. Strifeworld is a program that captures data transmitted as part of TCP connections and stores the data in a memory for analysis. Strifeworld reconstructs the actual data streams and stores each session in a file for later analysis.
- **SUCTIONCHAR**: 32 or 64 bit OS, solaris sparc 8,9, Kernel level implant - transparent, sustained, or realtime interception of processes input/output vnode traffic, able to intercept ssh, telnet, rlogin, rsh, password, login, csh, su, …
- **STOICSURGEON** Rootkit/Backdoor Linux MultiArchi
- **INCISION** Rootkit/Backdoor Linux Can be upgrade to StoicSurgeon(more recent version)

### CnC
- **Seconddate_CnC**: CnC for **SECONDDATE**
- **ELECTRICSIDE** likely a big-fat-ass CnC
- **NOCLIENT** Seems to be the CnC for **NOPEN***
- **DEWDROP** 

## Privesc

### Linux

- **h**: linux kernel privesc, old-day compiled `hatorihanzo.c`, do-brk() in 2.4.22  [CVE-2003-0961](https://nvd.nist.gov/vuln/detail/CVE-2003-0961)
- **gsh**: `setreuid(0,0);execl("bash","/bin/bash")`
- **PTRACE/FORKPTY**/**km3**: linux kernel lpe, kmod+ptrace, [CVE-2003-0127](https://nvd.nist.gov/vuln/detail/CVE-2003-0127), (https://mjt.nysv.org/scratch/ptrace_exploit/km3.c)
- **EXACTCHANGE**: NULL-deref based local-root, based on various sockets protocols, compiled in 2004, made public in 2005
- **ghost**:`statmon`/tooltalk privesc?
- **elgingamble**:
- **ESTOPFORBADE** local root `gds_inet_server` for, Cobalt Linux release 6.0, to be used with **complexpuzzle**
- **ENVOYTOMATO** LPE through bluetooth stack(?)
- **ESTOPMOONLIT** Linux LPE
- **EPOXYRESIN** Linux LPE

### AIX
- **EXCEEDSALON-AIX** privesc

### Others
- **procsuid**: setuid perl (yes, it's a real thing) privesc through unsanitized environnement variables. wtf dude
- **elatedmonkey**: cpanel privesc (0day) using `/usr/local/cpanel/3rdparty/mailman/`. Creates mailman mailing list: `mailman config_list`
- **estesfox**: logwatch privesc, [old-day](http://www.securiteam.com/exploits/5OP0S2A6KI.html)
- **evolvingstrategy**: privesc, likely for Kaspersky Anti-virus (`/sbin/keepup2date` is kaspersky's stuff) (what is `ey_vrupdate`?)
- **eh** OpenWebMail privesc
- **escrowupgrade** cachefsd for solaris 2.6 2.7 sparc
- **ENGLANDBOGY** local exploit against Xorg X11R7 1.0.1, X11R7 1.0, X11R6 6.9, Includes the following distributions: MandrakeSoft Linux 10.2, Ubuntu 5.0.4, SuSE Linux 10.0, RedHat Fedora Core5, MandrakeSoft Linux 2006.0. requires a setuid Xorg
- **endlessdonut**: Apache fastcgi privesc
