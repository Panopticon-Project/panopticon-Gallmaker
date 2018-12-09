![alt tag](https://user-images.githubusercontent.com/24201238/29351849-9c3087b4-82b8-11e7-8fed-350e3b8b4945.png)

# Panopticon Project

## Name - Gallmaker
* Label - Advanced Persistent Threat (APT)

Other names the threat actor is known by.
* [N/A](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)

## Overview 
A high level summary of the threat actor.
Use list
* Description goes here
*

## Time context starts

## Campaign or Date Range
* Date Range
* About - [Targeting the overseas embassies of an Eastern European nation, a Middle Eastern defense contractor and a military organization](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group) 
* Active from - 01 December 2017
* Active to - 30 June 2018

### Attributes
Listed after Camapign or Date Range as attributes can shift over time. Use one of the resource levels. Use one of the sophistication grades. Amateur is defined as using all prewritten tools and/or showing overall poor tradecraft. Expert is defined as using at least some self written tools and/or showing overall good tradecraft. Advanced Expert is defined as consistently using self written tools adnd showing consistently good tradecraft. Primary activity is a short description of what the groups mostly does.
* Resource level - [Government](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Sophistication - [Expert](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Primary activities - Description goes here

### Attack Pattern
* Initial Access 
  * [Spearphishing Attachment](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * The group delivers a malicious Office lure document to victims, most likely via a spear-phishing email. These lure documents use titles with government, military, and diplomatic themes, and the file names are written in English or Cyrillic languages. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe, including: bg embassy list.docx and Navy.ro members list.docx 
* Execution
  * [Dynamic Data Exchange](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content” (See Figure 1). Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system.
* Persistance
  * [Web Shell](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Once the Gallmaker attackers gain access to a device, they execute various tools. WindowsRoamingToolsTask is used to schedule PowerShell scripts and tasks. A "reverse_tcp" payload from Metasploit is used. The attackers use obfuscated shellcode that is executed via PowerShell to download this reverse shell. The Rex PowerShell library, which is publicly available on GitHub, is also seen on victim machines. This library helps create and manipulate PowerShell scripts for use with Metasploit exploits. 
* Privilege Escalation 
  * No information
* Defense Evasion 
  * No information
* Credential Access
  * No information
* Discovery
  * No information
* Lateral Movement
  * No information
* Collection
  * No information
* Exfiltration 
  * [Exfiltration Over Alternative Protocol](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * A legitimate version of the WinZip console: This creates a task to execute commands and communicate with the command-and-control (C&C) server. It’s likely this WinZip console is used to archive data, probably for exfiltration. WinZip supports FTP.
* Command and Control 
  * [Remote File Copy](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * A legitimate version of the WinZip console: This creates a task to execute commands and communicate with the command-and-control (C&C) server. It’s likely this WinZip console is used to archive data, probably for exfiltration.

### Vulnerabilities
* [No information](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)

### Identity

#### Individuals 
* [No information](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)

#### Affiliated organisations
* [No information](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)

#### Affiliated groups
* [No information](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)

### Intrusion Set
A grouped set of adversarial behaviors and resources with common properties believed to be orchestrated by a single threat actor. These are represented as individual categories under the heading of Intrusion Set. If an existing category does not cover what you need to add, contact a project mantainer on panopticonproject at protonmail dot com to add a section to Charon.

#### Malware
* Names - [No information](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Functionality - N/A
* Hash - N/A
* Notes - N/A

#### Website 
* Name - [No information](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* About - N/A
* URL - N/A
* IP - N/A
* Valid from - N/A
* Valid to - N/A

#### Command and Control Server
A server used by the attackers to send commands to malware and to receive commands and exfiltrated information from the malware.
* About - used by Even More Muffins malware to receive commands from and exfiltrate data to. IP addresses shouldhave square brackets [] arond the last separator so people don't accidentally navigate to the address. Dates should be in the format of DD Month Year e.g. 01 January 2019.
* IP - [111.90.149[.]99](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Valid from - [01 January 2018](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Valid to - [31 May 2018](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* SSH host key
  * RSA - no information
  * ECDSA - no information
  * ED25519 - no information
* SSL Certificate
  * Issuer - no information
  * Public key type - no information
  * Public key bits - no information
  * Signature algorithm - no information
  * Not valid before - no information
  * Not valid after - no information
  * MD5 - no information
  * SHA-1 - no information
* Notes - Date range given in source is December 2017 to June 2018. As there is no exact date given, it is possible activity related to this address in early December and late June could be related to a different party. A date range of 01 January 2018 to 31 May 2018 is given here to avoid misattribution.

* IP - [94.140.116[.]124](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Valid from - [01 January 2018](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Valid to - [31 May 2018](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* SSH host key
  * RSA - no information
  * ECDSA - no information
  * ED25519 - no information
* SSL Certificate
  * Issuer - no information
  * Public key type - no information
  * Public key bits - no information
  * Signature algorithm - no information
  * Not valid before - no information
  * Not valid after - no information
  * MD5 - no information
  * SHA-1 - no information
* Notes - Date range given in source is December 2017 to June 2018. As there is no exact date given, it is possible activity related to this address in early December and late June could be related to a different party. A date range of 01 January 2018 to 31 May 2018 is given here to avoid misattribution.

* IP - [94.140.116[.]231](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Valid from - [01 January 2018](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Valid to - [31 May 2018](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* SSH host key
  * RSA - no information
  * ECDSA - no information
  * ED25519 - no information
* SSL Certificate
  * Issuer - no information
  * Public key type - no information
  * Public key bits - no information
  * Signature algorithm - no information
  * Not valid before - no information
  * Not valid after - no information
  * MD5 - no information
  * SHA-1 - no information
* Notes - Date range given in source is December 2017 to June 2018. As there is no exact date given, it is possible activity related to this address in early December and late June could be related to a different party. A date range of 01 January 2018 to 31 May 2018 is given here to avoid misattribution.

#### Documents
* Filename - [bg embassy list.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artifacts on disk.
    Once the Gallmaker attackers gain access to a device, they execute various tools
* Hash - [Function] - [Actual hash](URL to source)
* Notes - 

* Filename - [Navy.ro members list.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artifacts on disk.
* Hash - [Function] - [Actual hash](URL to source)
* Notes - 

* Filename - [БГ в чуждите медии 23.03.2018-1.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artifacts on disk.
* Hash - [Function] - [Actual hash](URL to source)
* Notes - Tracked as W97M.Downloader

* Filename - [[REDACTED] and cae join forces to develop integrated live virtual constructive training solutions.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artifacts on disk.
* Hash - [Function] - [Actual hash](URL to source)
* Notes - Tracked as W97M.Downloader

* Filename - [А-9237-18-brasil.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artifacts on disk.
* Hash - [Function] - [Actual hash](URL to source)
* Notes - Tracked as W97M.Downloader

#### Tools
A tool used by the attacker. Multiple names should be listed on the same line and separated by a comma. Functionality should be short, preferably one word. Example: keylogger. Multiple functionalites should be listed on the same line and separated by a comma. URL should be the online address, if any, the tool can be publically sourced from.
* Names - [Name of malware](URL to source)
* Functionality - [Functionality, functionality] (URL to source)
* URL - http://address.com
W97M.Downloader
W97M.Downloader is a Word macro Trojan that downloads additional malware. W97M.Downloader is a malicious macro that may arrive as a Word document attachment in spam emails. When the Word document is opened, the macro attempts to download and execute malware from a remote location. Most spam campaigns spreading Dridex do so using attached Word documents containing a malicious macro. 
Symantec detects these malicious attachments as  
W97M.Downloader
. If this macro is allowed to run, a 
malicious .vbs file is dropped and executed. This file is detected as 
VBS.Downloader.Trojan
. . This malicious .vbs 
file will in turn download and install Dridex on the victim’s computer. 
## Time context ends 

### Detection
* [Spearphishing Attachment](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Network intrusion detection systems can be used to detect spearphishing with malicious attachments in transit.
  * Email gateways can be used to detect spearphishing with malicious attachments in transit. 
  * Detonation chambers may also be used to identify malicious attachments.  
  * Anti-virus can potentially detect malicious documents and attachments as they're scanned to be stored on the email server or on the user's computer. 
  * Endpoint sensing or network sensing can potentially detect malicious events once the attachment is opened (such as a Microsoft Word document or PDF reaching out to the internet or spawning Powershell.exe) for techniques such as Exploitation for Client Execution and Scripting.
* [Dynamic Data Exchange](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * OLE and Office Open XML files can be scanned for ‘DDEAUTO', ‘DDE’, and other strings indicative of DDE execution. 
  * Monitor for Microsoft Office applications loading DLLs and other modules not typically associated with the application.
  * Monitor for spawning of unusual processes (such as cmd.exe) from Microsoft Office applications. 
* [Web Shell](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Process monitoring may be used to detect Web servers that perform suspicious actions such as running cmd or accessing files that are not in the Web directory. 
  * File monitoring may be used to detect changes to files in the Web directory of a Web server that do not match with updates to the Web server's content and may indicate implantation of a Web shell script. Log authentication attempts to the server and any unusual traffic patterns to or from the server and internal network.
* [Exfiltration Over Alternative Protocol](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Follow best practices for network firewall configurations to allow only necessary ports and traffic to enter and exit the network. For example, if services like FTP are not required for sending information outside of a network, then block FTP-related ports at the network perimeter. 
  * Enforce proxies and use dedicated servers for services such as DNS and only allow those systems to communicate over respective ports/protocols, instead of all systems within a network. 
  * Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level. 
* [Remote File Copy](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Monitor for file creation and files transferred within a network over SMB. 
  * Unusual processes with external network connections creating files on-system may be suspicious. 
  * Use of utilities, such as FTP, that does not normally occur may also be suspicious. 
  * Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). 
  * Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. 
  * Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

### Course of Action 
* [Spearphishing Attachment](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Network intrusion prevention systems and systems designed to scan and remove malicious email attachments can be used to block activity. 
  * Block unknown or unused attachments by default that should not be transmitted over email as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some email scanning devices can open and analyze compressed and encrypted formats, such as zip and rar that may be used to conceal malicious attachments in Obfuscated Files or Information.
  * Users can be trained to identify social engineering techniques and spearphishing emails. 
  * To prevent the attachments from executing, application whitelisting can be used. 
  * Anti-virus can also automatically quarantine suspicious files.
* [Dynamic Data Exchange](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Registry keys specific to Microsoft Office feature control security can be set to disable automatic DDE/OLE execution. [1](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440) [2](https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/) [3](https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b).
  * Ensure Protected View is enabled and consider disabling embedded files in Office programs, such as OneNote, not enrolled in Protected View.
  * On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent DDE attacks and spawning of child processes from Office programs.
* [Web Shell](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Ensure that externally facing Web servers are patched regularly to prevent adversary access through Exploitation of Vulnerability to gain remote code access or through file inclusion weaknesses that may allow adversaries to upload files or scripts that are automatically served as Web pages.
  * Audit account and group permissions to ensure that accounts used to manage servers do not overlap with accounts and permissions of users in the internal network that could be acquired through Credential Access and used to log into the Web server and plant a Web shell or pivot from the Web server into the internal network.
* [Exfiltration Over Alternative Protocol](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Follow best practices for network firewall configurations to allow only necessary ports and traffic to enter and exit the network. For example, if services like FTP are not required for sending information outside of a network, then block FTP-related ports at the network perimeter. Enforce proxies and use dedicated servers for services such as DNS and only allow those systems to communicate over respective ports/protocols, instead of all systems within a network. 
  * Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. 
* [Remote File Copy](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions.
  
### Reports
Collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including contextual details. The description should be a short outline of the report.
Use list
* [Name of report](URL to pdf/blog post etc) - Description goes here
* [Name of report](URL to pdf/blog post etc) - Description goes here

## Copy and paste everything from Campaign or Date Range through to Reports for a new campaign or date range

## Raw Intelligence - start of footer
Any further notes to be added to the framework would be added here.

10 October 2018 https://www.securityweek.com/cyberspy-group-gallmaker-targets-military-government-organizations
A previously undocumented cyber espionage group has been targeting entities in the government, military and defense sectors since at least 2017, according to a report published on Wednesday by Symantec.
Symantec researchers noted that Gallmaker attacks appear highly targeted, with all known victims being related to the government, military or defense sectors.
Asked by SecurityWeek about links to other threat actors and the possible location of the hackers, Symantec noted that it tracks Gallmaker as a new cyber espionage group and said it had no information to share on who may be behind the attacks or where the attackers are located.
The security firm pointed out that Gallmaker is interesting because it does not use any actual malware in its operations and instead relies on publicly available tools – this is known in the industry as "living off the land."
The threat actor, tracked by the security firm as Gallmaker, has launched attacks on several overseas embassies of an unnamed Eastern European country, and military and defense organizations in the Middle East.
The group has been active since at least December 2017 and its most recent attacks were observed in June 2018 – a spike in Gallmaker activity was seen in April. Gallmaker has focused on cyber espionage and experts believe it's likely sponsored by a nation state.
Gallmaker attacks start with a specially crafted Office document most likely delivered via phishing emails. The documents are designed to exploit the Dynamic Update Exchange (DDE) protocol to execute commands in the memory of the targeted device.
"By running solely in memory, the attackers avoid leaving artifacts on disk, which makes their activities difficult to detect," Symantec's Attack Investigations Team wrote in a blog post.
Microsoft disabled DDE last year after malicious actors started exploiting it in their attacks. However, Symantec said Gallmaker victims failed to install the Microsoft update that disabled the problematic feature.
Once they gain access to a machine, the attackers use various tools to achieve their objectives. The list includes the reverse_tcp reverse shell from Metasploit, the WindowsRoamingToolsTask PowerShell scheduler, the WinZip console, and an open source library named Rex PowerShell, which helps create PowerShell scripts for Metasploit exploits.
Researchers also noticed that the attackers have deleted some of their tools from compromised machines once they were done, likely in an effort to hide their activities.

11 October 2018 https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group
Symantec researchers have uncovered a previously unknown attack group that is targeting government and military targets, including several overseas embassies of an Eastern European country, and military and defense targets in the Middle East. This group eschews custom malware and uses living off the land (LotL) tactics and publicly available hack tools to carry out activities that bear all the hallmarks of a cyber espionage campaign.
The group, which we have given the name Gallmaker, has been operating since at least December 2017, with its most recent activity observed in June 2018.
The most interesting aspect of Gallmaker’s approach is that the group doesn’t use malware in its operations.  Rather, the attack activity we observed is carried out exclusively using LotL tactics and publicly available hack tools. The group takes a number of steps to gain access to a victim’s device and then deploys several different attack tools, as follows:

    The group delivers a malicious Office lure document to victims, most likely via a spear-phishing email.
    These lure documents use titles with government, military, and diplomatic themes, and the file names are written in English or Cyrillic languages. These documents are not very sophisticated, but evidence of infections shows that they’re effective. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe, including:

    bg embassy list.docx
    Navy.ro members list.docx - maybe romania?

    These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content” (See Figure 1). Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artifacts on disk, which makes their activities difficult to detect.
    Once the Gallmaker attackers gain access to a device, they execute various tools, including:

    WindowsRoamingToolsTask: Used to schedule PowerShell scripts and tasks.
    A "reverse_tcp" payload from Metasploit: The attackers use obfuscated shellcode that is executed via PowerShell to download this reverse shell.
    A legitimate version of the WinZip console: This creates a task to execute commands and communicate with the command-and-control (C&C) server. It’s likely this WinZip console is used to archive data, probably for exfiltration.
    The Rex PowerShell library, which is publicly available on GitHub, is also seen on victim machines. This library helps create and manipulate PowerShell scripts for use with Metasploit exploits. 

Gallmaker is using three primary IP addresses for its C&C infrastructure to communicate with infected devices. There is also evidence that it is deleting some of its tools from victim machines once it is finished, to hide traces of its activity.

![alt tag](https://user-images.githubusercontent.com/24201238/49002038-557d6c80-f1c3-11e8-86c7-d3f5545070a3.png)

The DDE protocol can be used for legitimate purposes to send messages between Microsoft applications that share data through shared memory, e.g. to share data between Excel and Word. 

However, the DDE protocol was flagged as unsecure last year, when researchers discovered it could be exploited to execute code on victim machines via Excel and Word, without macros being enabled in those applications. Microsoft said at the time that this capability was a feature and the company did not consider it a vulnerability because Office always warned users before enabling DDE in documents, as seen in Figure 1. However, after the DDE protocol was subsequently exploited in a number of malware campaigns, Microsoft issued an update to Office in December 2017 that disabled DDE by default in Word and Excel. DDE can be enabled manually after this update is applied but only if the registry is altered by an admin account.

The Gallmaker victims we have seen did not have this patch installed and therefore were still vulnerable to exploit via the DDE protocol.
Gallmaker’s activity appears to be highly targeted, with its victims all related to government, military, or defense sectors. Several targets are embassies of an Eastern European country. The targeted embassies are located in a number of different regions globally, but all have the same home country.

The other targets we have seen are a Middle Eastern defense contractor and a military organization. There are no obvious links between the Eastern European and Middle Eastern targets, but it is clear that Gallmaker is specifically targeting the defense, military, and government sectors: its targets appear unlikely to be random or accidental.

Gallmaker’s activity has been quite consistent since we started tracking it. The group has carried out attacks most months since December 2017. Its activity subsequently increased in the second quarter of 2018, with a particular spike in April 2018.
Gallmaker’s activity points strongly to it being a cyber espionage campaign, likely carried out by a state-sponsored group.
The fact that Gallmaker appears to rely exclusively on LotL tactics and publicly available hack tools makes its activities extremely hard to detect. We have written extensively about the increasing use of LotL tools and publicly available hack tools by cyber criminals. One of the primary reasons for the increased popularity of these kinds of tools is to avoid detection; attackers are hoping to “hide in plain sight”, with their malicious activity hidden in a sea of legitimate processes.
The following protections are in place to protect customers against Gallmaker attacks:

    System Infected: Meterpreter Reverse TCP

    W97M.Downloader

Network protection products also detect activity associated with Gallmaker.
Indicators of Compromise

The following indicators are specific to Gallmaker:
Network

    111[.]90.149.99/o2
    94[.]140.116.124/o2
    94[.]140.116.231/o2

Filenames

    bg embassy list.docx
    Navy.ro members list.docx
    БГ в чуждите медии 23.03.2018-1.docx
    [REDACTED] and cae join forces to develop integrated live virtual constructive training solutions.docx
    А-9237-18-brasil.docx

Gallmaker also used tools that were available in open source projects. Yara rule and methods shared below were used by Gallmaker but aren't exclusive to the group's activity. Detection of these in one's environment is only indicative of possible unauthorized activity. Each occurrence of triggers must be examined to determine intent.

rule Suspicious_docx
{
meta:
copyright = "Symantec"
family = "Suspicious DOCX”
group = "Gallmaker"
description = "Suspicious file that might be Gallmaker”

strings:
$quote = /<w:fldSimple w:instr=" QUOTE (( [^"]+)* [0-9]

{2,3}

)

{4}

/
$text = "select \"Update field\" and click \"OK\""

condition:
any of them
}

Use of Rex Powershell - https://github.com/rapid7/rex-powershell

Use of obfuscated shellcode executed via PowerShell to download a "reverse_tcp" payload from Metasploit
onto victim systems. For example, msfvenom -p windows/meterpreter/reverse_tcp -o payload.bin
## Links - end of footer
Any new articles would be added here.

https://www.securityweek.com/cyberspy-group-gallmaker-targets-military-government-organizations
