![alt tag](https://user-images.githubusercontent.com/24201238/29351849-9c3087b4-82b8-11e7-8fed-350e3b8b4945.png)

# Panopticon Project

## Name - Gallmaker
* Label - Advanced Persistent Threat (APT)

Other names the threat actor is known by.
* [No information](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)

## Overview 
* As of October 2018, Gallmaker has targeted government and military targets, including several overseas embassies of an Eastern European country, and military and defence targets in the Middle East.
* The group uses living off the land (LotL) tactics and publicly available tools to carry out activities
* The goal of the group appears to be espionage 

## Time context starts

## Campaign or Date Range
* Date Range
* About - [Targeting the overseas embassies of an Eastern European nation, a Middle Eastern defence contractor and a military organisation](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group) 
* Active from - 01 December 2017
* Active to - 30 June 2018

### Attributes
* Resource level - [Government](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Sophistication - [Expert](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
* Primary activities - Exfiltration of information held by embassies and military organisations

### Attack Pattern
* Initial Access 
  * [Spearphishing Attachment](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * The group delivers a malicious Office lure document to victims, most likely via a spear-phishing email. These lure documents use titles with government, military, and diplomatic themes, and the file names are written in English or Cyrillic languages. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe, including: bg embassy list.docx and Navy.ro members list.docx 
* Execution
  * [Dynamic Data Exchange](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content” (See Figure 1). Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system.
* Persistence
  * [Web Shell](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Once the Gallmaker attackers gain access to a device, they execute various tools. WindowsRoamingToolsTask is used to schedule PowerShell scripts and tasks. A "reverse_tcp" payload from Metasploit is used. The attackers use obfuscated shellcode that is executed via PowerShell to download this reverse shell. The Rex PowerShell library, which is publicly available on GitHub, is also seen on victim machines. This library helps create and manipulate PowerShell scripts for use with Metasploit exploits. 
* Privilege Escalation 
  * No information
* Defence Evasion 
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
  * About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artifacts on disk. Once the Gallmaker attackers gain access to a device, they execute various tools.
  * Hash - No information
  * Notes - Tracked as W97M.Downloader

* Filename - [Navy.ro members list.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artefacts on disk. Once the Gallmaker attackers gain access to a device, they execute various tools.
  * Hash - No information
  * Notes - Tracked as W97M.Downloader

* Filename - [БГ в чуждите медии 23.03.2018-1.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artefacts on disk. Once the Gallmaker attackers gain access to a device, they execute various tools.
  * Hash - No information
  * Notes - Tracked as W97M.Downloader

* Filename - [[REDACTED] and cae join forces to develop integrated live virtual constructive training solutions.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artefacts on disk. Once the Gallmaker attackers gain access to a device, they execute various tools.
  * Hash - No information
  * Notes - Tracked as W97M.Downloader

* Filename - [А-9237-18-brasil.docx](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * About - The group delivers a malicious Office lure document to victims. These lure documents use titles with government, military, and diplomatic themes. The attackers use filenames that would be of interest to a variety of targets in Eastern Europe. These lure documents attempt to exploit the Microsoft Office Dynamic Data Exchange (DDE) protocol in order to gain access to victim machines. When the victim opens the lure document, a warning appears asking victims to “enable content”. Should a user enable this content, the attackers are then able to use the DDE protocol to remotely execute commands in memory on the victim’s system. By running solely in memory, the attackers avoid leaving artefacts on disk. Once the Gallmaker attackers gain access to a device, they execute various tools.
  * Hash - No information
  * Notes - Tracked as W97M.Downloader

#### Tools
* Names - [W97M.Downloader](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Functionality - Downloads and executes malware from a remote location
  * URL - https://docs.microsoft.com/en-us/windows/desktop/dataxchg/about-dynamic-data-exchange

* Names - [WindowsRoamingToolsTask](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Functionality - Schedule PowerShell scripts and tasks
  * URL - https://social.technet.microsoft.com/wiki/contents/articles/38580.configure-to-run-a-powershell-script-into-task-scheduler.aspx

* Names - [reverse_tcp payload](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Functionality - Obfuscated shellcode that is executed via PowerShell to download a reverse shell
  * URL - https://www.winzip.com/win/en/downcl.html

* Names - [Ruby Exploitation(Rex) Powershell library](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Functionality - Creates and manipulates PowerShell scripts for use with Metasploit exploits
  * URL - https://github.com/rapid7/rex-powershell

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
  * Analyse network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). 
  * Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. 
  * Analyse packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

### Course of Action 
* [Spearphishing Attachment](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group)
  * Network intrusion prevention systems and systems designed to scan and remove malicious email attachments can be used to block activity. 
  * Block unknown or unused attachments by default that should not be transmitted over email as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some email scanning devices can open and analyse compressed and encrypted formats, such as zip and rar that may be used to conceal malicious attachments in Obfuscated Files or Information.
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
  * Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool and will likely be different across various malware families and versions.

### YARA rules
Rules for detecting indicators of compromise. State no information where the rule would be pasted if no information is available.
Use list
* Rule - Paste on next line
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
* URL - https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group

### Reports
* [Gallmaker: New Attack Group Eschews Malware to Live off the Land](https://www.symantec.com/blogs/threat-intelligence/gallmaker-attack-group) - Symantec researchers have uncovered a previously unknown attack group that is targeting government and military targets, including several overseas embassies of an Eastern European country, and military and defence targets in the Middle East. This group eschews custom malware and uses living off the land (LotL) tactics and publicly available hack tools to carry out activities that bear all the hallmarks of a cyber espionage campaign.

## Raw Intelligence 
Any further notes to be added to the framework to be added here.
