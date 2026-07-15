# TryHackMe Writeups

Penetration testing lab writeups covering enumeration, exploitation, and privilege escalation across a range of machine difficulties.

**TryHackMe profile:** [tryhackme.com/p/1olyaprivet1](https://tryhackme.com/p/1olyaprivet1) · Top 1%

---

## Skills Demonstrated

- Network enumeration and service fingerprinting (nmap, gobuster/ffuf)
- Web application testing — SQLi, XXE, command injection, cookie/session manipulation
- NFS and FTP misconfiguration exploitation
- Privilege escalation — `LD_LIBRARY_PATH` hijacking, SUID abuse, sudo misconfigurations
- Custom Python scripting for attack automation
- Reverse shell deployment and post-exploitation

---

## Writeups

| Machine | Difficulty | Key Techniques |
|---------|------------|----------------|
| [Hijack](./🟢Hijack.md) | 🟢 Easy | NFS misconfiguration, cookie brute-force (MD5/Base64), LD_LIBRARY_PATH hijack |
| [Opacity](./🟢Opacity.md) | 🟢 Easy | File upload bypass, PHP reverse shell, cron-based privesc |
| [Plotted-TMS](./🟢Plotted-TMS.md) | 🟢 Easy | SQL injection, web shell upload |
| [Proxy](./🟢Proxy.md) | 🟢 Easy | SSRF, internal service enumeration |
| [Publisher](./🟢Publisher.md) | 🟢 Easy | SSTI, AppArmor profile bypass |
| [Team](./🟢Team.md) | 🟢 Easy | LFI, credential reuse, SSH key extraction |
| [UA High School](./🟢UA_High_School.md) | 🟢 Easy | WordPress exploitation, steganography |
| [Lookup](./🟢lookup.md) | 🟢 Easy | Credential brute-force, elFinder RCE, sudo path abuse |
| [Annie](./🟡Annie.md) | 🟡 Medium | AnyDesk RCE (CVE-2021-40655), SSH key cracking |
| [Domino](./🟡Domino.md) | 🟡 Medium | HCL Domino enumeration, DMARC bypass |
| [Forward](./🟡Forward.md) | 🟡 Medium | Squid proxy pivoting, internal network traversal |
| [New York Flankees](./🟡New_York_Flankees.md) | 🟡 Medium | Padding oracle attack, Docker escape |
| [Oh My Webserver](./🟡Oh_my_webserver.md) | 🟡 Medium | Apache mod_cgi RCE (CVE-2021-41773), Python capabilities privesc |
| [Ollie](./🟡Ollie.md) | 🟡 Medium | phpIPAM SQLi, Phar deserialization, sudo abuse |
| [Umbrella](./🟡Umbrella.md) | 🟡 Medium | Docker Registry enumeration, Node.js SSTI, volume mount escape |
| [VulnNet Endgame](./🟡vulnnet_engame.md) | 🟡 Medium | Redis exploitation, wildcard injection |

---

> Writeups are written in Russian. Assumed baseline: Linux terminal proficiency, familiarity with common pentesting tools and frameworks, and understanding of frequently exploited vulnerabilities.
