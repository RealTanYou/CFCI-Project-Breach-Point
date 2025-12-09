This project and program was written and created for the Centre for Cyberseucurity Insitutute, Vocational Training Programme, Pentesting Module, SOC Essentials Module and Windows Forensics Modules.

The project is split into three parts:

1. A pentesting script that is able to do the following:
   a. Reconnaissance and Information Gathering by scanning networks and enumerating ports and services using nmap
   b. Vulnerability assessment by automatically looking up CVEs on the results of Reconanissance
   c. Exploitation by using MSFconsole and MSFvevnom to generate exploits, and
   d. Exfiltration by generating commands that lets users automatiicaly find files and send them back to the user.
2. A network that has the following:
   a. A pfSense firewall that divides an internal and external network, with Snort installed.
   b. A Domain Controller to act as a main target of data exfiltration, and where most event logs would be.
   c. A Windows Client, which will serve as another user wihtin the network that can be targetted.
   b. A SIEM Elastic Stack server that is able to ingest logs from the DC server, Windows client, pfSense and Snort.
3. An analysis script that is able to do the following:
   a. Extract logs, registry hives, user history, system history and files from a memory image
   b. Analyze the output for potential signs of indicators of compromise.

The maim aim of this project is to demonstrate how a full attack, detection, analysis and recovery of an attack could function, by simulating both an attacker, a vulnerable network, and a victim machine to analyze the attack from.
