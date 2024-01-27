# Trabalho realizado nas Semanas #2 e #3

## Identificação

- CVE-2015-1701
- Win32k.sys in the kernel-mode drivers allows local users to gain privileges via a crafted application.
- Affected systems: Microsoft Windows Server 2003 SP2, Microsoft Windows Vista SP2, Microsoft Windows Server 2008 SP2 and Microsoft Windows 7.

## Catalogação

- Exploited in 2015-04-21 by Microsoft Corporation.
- It is also known as "Win32k Elevation of Privilege Vulnerability".
- It has a base score of 7.2 (High) according to NVD.

## Exploit

- Metasploit module is the "Windows ClientCopyImage Win32k Exploit".
- This module exploits improper object handling in the win32k.sys kernel mode driver. 
- This module has been tested on vulnerable builds of Windows 7 x64 and x86, and Windows 2008 R2 SP1 x64.
- Upgrading to version 8, 8.1 or Server 2012 eliminates this vulnerability.


## Ataques

- The most famous attack is called Operation RussianDoll.
- The attack needs to be approached locally and a single authentication is required for exploitation.
