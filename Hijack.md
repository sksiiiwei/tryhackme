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
Есть возможность посмотреть сетевую файловую систему (nfs), воспользуемся ей

``` Show mount -e 10.112.138.240 ```
Там лежит /share/mount *. Монтируем к себе. Открыть не удалось даже под рутом - включена защита nsf.
Значит, посмотрим сайт на 80 порту. Сразу посмотрим директории через ффаф. Там тоже ничего интересного 

<img width="1025" height="622" alt="image" src="https://github.com/user-attachments/assets/d308331d-4fa5-430b-b7bd-b6b31ac3908d" />

Сам сайт небольшой - стандартное поле ввода и админская панель, к которой доступа у нас нет(only the admin can access this page). 
Прогнала через форму логина sqlmap, посмотрела запросы через бурп, быстро просмотрела код страничек - ничего интересного.

<img width="557" height="193" alt="image" src="https://github.com/user-attachments/assets/852c4695-6bfa-4597-a369-c9eb8ff42e4c" />

Но у нас есть форма регистрации и понимание, что нам вероятнее всего нужно получить доступ к аккаунту админа. И вот мы проверяем форму регистрации
и получаем приятный результат (сейчас увидела, что корректность .хернейма подтверждается и при попытке залогиниться). Но брутфорсить не выйдет из-за ограничения
на ввод пароля (5 попыток)

<img width="651" height="259" alt="image" src="https://github.com/user-attachments/assets/fd0132c8-ba96-44cb-abfc-f7e110d12672" />







