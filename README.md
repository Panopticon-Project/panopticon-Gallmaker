## Name - start of header
Common name of the threat actor. Use one of the listed labels.
* Label - Advanced Persistent Threat (APT) / Corporation / Nation State

## Aliases
Other names the threat actor is known by.
Use list
* [Alias](URL to source)
* [Alias](URL to source)

## Overview - end of header
A high level summary of the threat actor.
Use list
* Description goes here
*

## Campaign or Date Range - start of repeatable time contextual section 
Use either a campaign with a specific timeframe or a date range not associated with a specifc campaign. About is a short description of the campaign and should be removed if using date range. Dates should be in the format of DD Month Year e.g. 01 January 2019.
* Campaign / Date Range
* About - [Targetting infrastructure in South East Asia](URL to source) / Remove is using date range
* Active from - XX Month 20XX
* Active to - XX Month 20XX

### Attributes
Listed after Camapign or Date Range as attributes can shift over time. Use one of the resource levels. Use one of the sophistication grades. Amateur is defined as using all prewritten tools and/or showing overall poor tradecraft. Expert is defined as using at least some self written tools and/or showing overall good tradecraft. Advanced Expert is defined as consistently using self written tools adnd showing consistently good tradecraft. Primary activity is a short description of what the groups mostly does.
* Resource level - [Individual / Group / Corporation / Government](URL to source)
* Sophistication - [Amateur / Expert / Advanced Expert](URL to source)
* Primary activities - Description goes here

### Attack Pattern
A type of Tactics, Techniques, and Procedures (TTP) that describes ways threat actors attempt to compromise targets. Malware should have a short escription and be detailed below.
Use list
* [Attack Pattern](URL to source)
* [Attack Pattern](URL to source)
* Malware - Description goes here


### Vulnerabilities
A mistake in software that can be directly used by an attacker to gain access to a system or network. Link to a writeup in the exploit repo where possible (example, CVEs) or to external sources. Format should be in the format of ulnerability is exploited by name of the thing exploiting it, usually malware or a hacking tool.
Use list
* [Vulnerabilty](URL to outline of how vulnerability is exploited) is exploited by name of malware / name of tool
* [Vulnerabilty](URL to outline of how vulnerability is exploited) is exploited by name of malware / name of tool

### Course of Action 
An action taken to either prevent an attack or respond to an attack. If the course of action is connected to something in this report, such as a CVE for example, that should be referenced. Example: Apply patch 5678 to ICS systems to patch CVE-2019-0254.
Use list
* Description goes here
*

### Identity
Individuals, organizations, or groups. These are represented as individual entries under the heading of Identity.

#### Individuals 
Specific members of 
Use list
* [Name](URL to source)
* [Name](URL to source)

#### Affiliated organisations
Use list
* [Organisation](URL to source)
* [Organisation](URL to source)

#### Affiliated groups
Use list
* [Group](URL to source)
* [Group](URL to source)

### Intrusion Set
A grouped set of adversarial behaviors and resources with common properties believed to be orchestrated by a single threat actor. These are represented as individual categories under the heading of Intrusion Set. If an existing category does not cover what you need to add, contact a project mantainer on panopticonproject at protonmail dot com to add a section to Charon.

#### Malware
Details of malware used. Multiple names should be listed on the same line and separated by a comma. Functionality should be short, preferably one word. Example: keylogger. Multiple functionalites should be listed on the same line and separated by a comma. Hash should have a -, the type of hashing function used, another -, and the hash itself. Example: Hash - MD5 - 002ae76872d80801692ff942308c64t6. Notes should be a short description of anything else important, like the family the malware belongs to or variants.
* Names - [Name of malware](URL to source)
* Functionality - [Functionality, functionality] (URL to source)
* Hash - [Function] - [Actual hash](URL to source)
* Notes - Description goes here

#### Website 
A website used by the attacker. URLs should be in the format of hxxp so people don't accidentablly navigate to the URL by clicking on it. IP addresses shouldhave square brackets [] arond the last separator so people don't accidentally navigate to the address. Dates should be in the format of DD Month Year e.g. 01 January 2019.
* About - Description goes here
* URL - [hxxp://address[.]com](URL to source)
* IP - [000.000.000[.]000](URL to source)
* Valid from - [XX Month 20XX](URL to source)
* Valid to - [XX Month 20XX](URL to source)

#### Command and Control Server
A server used by the attackers to send commands to malware and to receive commands and exfiltrated information from the malware.
* About - used by Even More Muffins malware to receive commands from and exfiltrate data to. IP addresses shouldhave square brackets [] arond the last separator so people don't accidentally navigate to the address. Dates should be in the format of DD Month Year e.g. 01 January 2019.
* IP - [000.000.000[.]000](URL to source)
* Valid from - [XX Month 20XX](URL to source)
* Valid to - [XX Month 20XX](URL to source)

#### Documents
A document used by the attackers, usually as part of phishing. About should be a short description of how the document was used. Hash should have a -, the type of hashing function used, another -, and the hash itself. Example: Hash - MD5 - 002ae76872d80801692ff942308c64t6.
* About - Description goes here
* Hash - [Function] - [Actual hash](URL to source)

#### Tools
A tool used by the attacker. Multiple names should be listed on the same line and separated by a comma. Functionality should be short, preferably one word. Example: keylogger. Multiple functionalites should be listed on the same line and separated by a comma. URL should be the online address, if any, the tool can be publically sourced from.
* Names - [Name of malware](URL to source)
* Functionality - [Functionality, functionality] (URL to source)
* URL - http://address.com

### Reports - emd of repeatable time contextual section 
Collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including contextual details. The description should be a short outline of the report.
Use list
* [Name of report](URL to pdf/blog post etc) - Description goes here
* [Name of report](URL to pdf/blog post etc) - Description goes here

## Copy and paste everything from Campaign or Date Range through to Reports for a new campaign or date range

## Raw Intelligence - start of footer
Any further notes to be added to the framework would be added here.

## Links - end of footer
Any new articles would be added here.

https://www.securityweek.com/cyberspy-group-gallmaker-targets-military-government-organizations
