<?php
// Прокси распознавания для ru.homecatalog.garant.
// Спецификация: docs/superpowers/specs/2026-09-28-ai-proxy-php-design.md
//
// Ключи провайдеров лежат в ai-config.php. Исходник PHP по HTTP не отдаётся —
// сервер выполняет файл и возвращает только вывод, поэтому содержимое конфига
// недоступно извне. Это перестаёт быть верным, если рядом остались .bak/.old/~.

// На шэред-хостинге display_errors бывает On, и тогда любая warning дописывается
// к выводу: клиент получает HTML вместо JSON, а наружу уезжают пути на сервере.
// Отключаем до первого обращения к require. log_errors включаем принудительно:
// на части шэредов display_errors=0 и log_errors=0 стоят одновременно, и тогда
// все warning'и исчезают без следа — разбор «почему 503» превращается в гадание.
@ini_set('display_errors', '0');
@ini_set('log_errors', '1');

define('AI_PROXY_CONFIG', require __DIR__ . '/ai-config.php');

// Потолок апстрима для движка без собственного слайса. Все боевые движки
// берут ENGINE_TIMEOUT ниже, а не это число.
const UPSTREAM_TIMEOUT = 28;
const CONNECT_TIMEOUT = 8;
// Бюджеты движков цепочки: клиент шлёт один запрос и ждёт цепочку целиком,
// поэтому движки получают свои слайсы, а не долю дележа route_timeout.
// Запас до потолка приложения — на пересборку тела и передачу ответа.
//
// Ключ здесь — имя движка, а не его позиция в цепочке. Цепочку и её порядок
// держит путь /ai/v1 (движки local -> opencode -> openrouter), и только он.
// Перестановка движков местами трогает здесь массив и ничего больше.
//
// Числа держатся в паре с потолком RecognitionService.overallTimeout:
// сумма ENGINE_TIMEOUT (13+43+13 = 69) + запас 11 с = 80. Поднять одно молча
// нельзя — приложение срежет ответ раньше, чем прокси его отдаст.
// Движков с двумя и более маршрутами здесь быть не должно: route_timeout
// режет их на доли, и длинные генерации снова начнут умирать (см. ai-config.php).
const ENGINE_TIMEOUT = array('local' => 13, 'opencode' => 43, 'openrouter' => 13);
const MAX_BODY_BYTES = 8388608;
// Лимит поднят решением владельца с 6 до 30: за одним публичным IP мобильного
// оператора сидят сотни абонентов, и 6 в минуту доставалось бы примерно трём
// чекам на весь сегмент.
const RATE_LIMIT_PER_MINUTE = 30;

// Локальная модель отвечает за ~4 с, но на холодной загрузке и под нагрузкой
// от ПК владельца бывает и 10. Взят с запасом: это единственный движок,
// после которого цепочка всё равно идёт дальше, а не возвращается клиенту.
// Сколько провайдер лежит в паузе после неудачи. За это время его не опрашиваем
// и уходим к следующему сразу, не тратя клиентский бюджет на ожидание.
// 30с - компромисс: холодная локалка успевает прогреться и вернуться в строй
// быстро, а реально лёгший хост не заставляет ждать полный таймаут подряд.
const PROVIDER_COOLDOWN = 30;
// Сколько живёт отметка «локальный движок доступен» от ПК владельца.
//
// Механика: выключенный ПК не может сообщить серверу, что он выключен, — об
// этом узнают только постфактум, по отсутствию отметки. ПК при старте шлёт
// один POST, дальше подтверждает его каждые несколько минут. Пока подтверждения
// идут — движок считается живым и работает без задержки; как только они
// прекратились, проходит TTL и движок пропускается мгновенно.
//
// TTL заметно больше интервала подтверждения, а не наоборот: пара пропущенных
// пингов из-за сна ноутбука или потери сети не должна выкидывать живой движок и
// заставлять ждать полный таймаут там, где всё работает.
const LOCAL_ALIVE_TTL = 900;
// Возраст файла счётчика, после которого он считается мусором. Окно счётчика —
// минута, и новое окно стартует с нуля, не читая прежнее состояние, то есть
// файл старше часа не прочитает ни один будущий запрос.
const RATE_STALE_AFTER = 3600;

function respond_json($status, array $body) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($body, JSON_UNESCAPED_UNICODE);
    exit;
}

// Отказ самого прокси обязан попадать в лог. Запись апстрима выше пишется по
// каждому дошедшему до cURL запросу, а 404/405/413/400/429 ответа не имеют и
// в логе не видны совсем. У публичного эндпоинта единственный контроль затрат —
// лимит по IP, и без этих строк нельзя отличить «клиент увидел 429» от «клиент
// не пришёл»: второй случай не оставляет следов нигде. В лог уходят engine,
// путь, код и имя ошибки; IP хэшируется, как и в основной записи, значения,
// тела и заголовки не пишутся. Путь чистится от непечатаемых символов, иначе
// клиент дописал бы в лог свою строку.
function log_reject($engine, $path, $status, $error) {
    $clean_path = preg_replace('/[^0-9A-Za-z._\/-]/', '', (string)$path);
    error_log(sprintf(
        'ai_proxy reject engine=%s path=%s status=%d reason=%s',
        ((string)$engine === '') ? '-' : (string)$engine,
        ($clean_path === '') ? '-' : $clean_path,
        (int)$status,
        $error
    ));
}

/**
 * Настоящий IP клиента.
 *
 * Сайт стоит за Cloudflare, поэтому REMOTE_ADDR - это адрес edge-сервера, а не
 * пользователя. Считать лимит по нему нельзя: тогда все пользователи делят
 * один счётчик, и 31-й запрос получает 429.
 *
 * CF-Connecting-IP берём только если запрос действительно пришёл от Cloudflare.
 * Иначе любой желающий подставит заголовок и обойдёт лимит.
 */
define('CF_EDGE_RANGES', array(
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
));

function ip_in_ranges($ip, $ranges) {
    $packed = @inet_pton($ip);
    if ($packed === false) {
        return false;
    }
    foreach ($ranges as $cidr) {
        list($net, $bits) = explode('/', $cidr, 2);
        $netPacked = @inet_pton($net);
        if ($netPacked === false || strlen($netPacked) !== strlen($packed)) {
            continue;
        }
        $bits = (int)$bits;
        if ($bits <= 0) {
            return true;
        }
        // Сравниваем побитово: достаточно первых ceil(bits/8) байт + маска хвоста
        $fullBytes = intdiv($bits, 8);
        $restBits = $bits % 8;
        if ($fullBytes > 0 && strncmp($packed, $netPacked, $fullBytes) !== 0) {
            continue;
        }
        if ($restBits > 0) {
            $mask = chr((0xFF << (8 - $restBits)) & 0xFF);
            if (($packed[$fullBytes] & $mask) !== ($netPacked[$fullBytes] & $mask)) {
                continue;
            }
        }
        return true;
    }
    return false;
}

/**
 * Список попыток: провайдер -> перечень моделей.
 *
 * Основной провайдер идёт со своей цепочкой моделей, потом запасные. Модели в
 * цепочке нужны потому, что у провайдера пропадает отдельная модель (снимают,
 * лимиты, перегрузка), и тогда клиент получает 503 вместо результата: с
 * единственной моделью запасного нет. У OpenCode Go /models отдаёт 30 позиций,
 * но наличие в списке не значит, что модель принимает картинку - часть
 * отвечает 400 на image_url, поэтому перебор идёт вслепую и по коду ответа.
 */
/**
 * Электрический размыкатель на провайдера.
 *
 * Зачем. Без него цепочка линейная: запрос уходит на opencode.ai, тот
 * молчит, и клиент ждёт полный таймаут, прежде чем мы вообще узнаем, что
 * провайдер лежит. Измерения показывали 22с на удачный opencode и 37с на
 * цепочку, ушедшую в openrouter только после истечения таймаута. Владелец
 * просил переключаться сразу, не дожидаясь.
 *
  * После неудачи провайдер пропускается на PROVIDER_COOLDOWN секунд: запрос
  * уходит к следующему без потери времени. Это работает со второго запроса -
  * первый по определению платит таймаут, узнать о падении иначе нельзя.
  *
  * Исключение — медленная локалка (только движок local): израсходован почти
  * весь бюджет, но хост жив. Чаще всего это холодная модель, которая к
  * следующему запросу уже прогрета, — пауза её не касается, см. ниже.
 *
 * Состояние в sys_get_temp_dir(), тем же способом, что счётчик rate-limit,
 * и с тем же суффиксом от предсказуемого имени каталога. Записи по хостам
 * провайдеров, а не по ip и не по ключам: ключ в имени не участвует.
 */
// rate_state_suffix() объявлена ниже по файлу, чем здесь нужно, - PHP для
// функций это допускает (подъём объявления есть на этапе выполнения файла),
// но вызовы идут только во время обработки запроса, когда все функции уже
// объявлены. Порядок в файле оставлен как есть ради истории правок.

function provider_state_file($host) {
    $token = rate_state_suffix();
    return rtrim(sys_get_temp_dir(), '/\\') . '/garant-ai-prov-' . $token . '-' . substr(sha1((string)$host), 0, 16) . '.ts';
}

/**
 * Провайдер на паузе? Возвращает время, когда пауза кончится (unix ts).
 * Второй элемент - признак «все маршруты на паузе, надо попробовать хоть один».
 */
function provider_in_cooldown($host, &$allCooling) {
    $allCooling = false;
    $f = provider_state_file($host);
    $raw = @file_get_contents($f);
    if ($raw === false || $raw === '') {
        return 0;
    }
    $until = (int)trim($raw);
    if ($until <= time()) {
        @unlink($f);
        return 0;
    }
    $allCooling = true;
    return $until;
}

function provider_mark_failure($host) {
    $until = time() + PROVIDER_COOLDOWN;
    $f = provider_state_file($host);
    $h = @fopen($f, 'w');
    if ($h === false) {
        return;
    }
    @fwrite($h, (string)$until);
    @fflush($h);
    @flock($h, LOCK_UN);
    @fclose($h);
}

function provider_mark_success($host) {
    @unlink(provider_state_file($host));
}

/**
 * Живость локального движка: отметка от ПК владельца.
 *
 * Зачем. Пауза PROVIDER_COOLDOWN экономит таймаут со второго запроса, но
 * первый после окна всё равно платит полные 13 с, а пачка одновременных
 * запросов успевает разлететься до того, как пауза появится. Когда локальный
 * движок выключен намеренно и временно, ждать таймаут незачем: нужен
 * мгновенный переход на следующий шаг, то есть 503 без похода в сеть.
 *
 * Раньше здесь стоял ручной выключатель — файл-метка, которую владелец
 * создавал и удалял руками. У владельца нет SSH, значит файл нечем создать,
 * и та схема была неисполнимой на практике: выключить движок можно, включить
 * обратно нельзя. Поэтому отметку шлёт сам ПК: при старте и дальше раз в
 * несколько минут.
 *
 * Состояние — время последнего подтверждения в sys_get_temp_dir(), тем же
 * способом и с тем же суффиксом от ключа, что счётчик rate-limit: вне
 * веб-рута, соседний аккаунт на шаре имя не угадает. Значение читается как
 * целое unix-время, а не как время изменения файла: mtime переживает
 * перенос файла между аккаунтами и может оказаться старше содержимого.
 *
 * Отсутствие отметки и есть «движка нет», и для локального это единственный
 * способ узнать о выключенном ПК: сам выключенный компьютер сообщить о
 * выключении не может. Облачные движки живут всегда и отметки не ждут, иначе
 * перезагрузка ПК владельца выключила бы весь резерв.
 */
function local_alive_file() {
    $token = rate_state_suffix();
    return rtrim(sys_get_temp_dir(), '/\\') . '/garant-ai-local-alive-' . $token . '.ts';
}

function local_alive() {
    $raw = @file_get_contents(local_alive_file());
    if (!is_string($raw) || $raw === '') {
        return false;
    }
    $seen = (int)trim($raw);
    if ($seen <= 0) {
        return false;
    }
    return (time() - $seen) < LOCAL_ALIVE_TTL;
}

function local_mark_alive() {
    return @file_put_contents(local_alive_file(), (string)time()) !== false;
}

/**
 * Движок не обслуживается сейчас: клиент получит быстрый 503 и уйдёт на
 * следующий шаг цепочки, не тратя ни секунды на сеть.
 *
 * Только движок из закрытого списка $engines: имя приходит не от клиента, но
 * проверка делает галочку бесполезной для любого мусора в имени.
 */
function engine_inactive($engine) {
    $known = array('local', 'opencode', 'openrouter', 'external');
    if (!in_array((string)$engine, $known, true)) {
        return false;
    }
    if ((string)$engine === 'local') {
        return !local_alive();
    }
    return false;
}

/**
 * Конфиг движка из ai-config.php. isset, а не прямая выборка: отсутствие
 * секции должно давать внятный 503 с записью в лог, а не notice и молчаливый
 * обрыв дальше по коду. Форма $config ничем не гарантирована: смена формы
 * конфига дала бы notice'ы и молчаливый 503 без диагностики. Проверяем
 * обязательные поля явно, логируем имена недостающих (не значения — там
 * ключ провайдера). Битый движок пропускается, а не роняет всю цепочку.
 */
function engine_config($engine) {
    $config = isset(AI_PROXY_CONFIG[$engine]) ? AI_PROXY_CONFIG[$engine] : null;
    $required = ((string)$engine === 'local')
        ? array('url', 'key', 'model', 'num_ctx')
        : array('url', 'key', 'model');
    $missing = array();
    if (!is_array($config)) {
        $missing[] = 'engine_section';
    } else {
        foreach ($required as $field) {
            if (!isset($config[$field]) || $config[$field] === '') {
                $missing[] = $field;
            }
        }
    }
    if (!empty($missing)) {
        error_log(sprintf(
            'ai_proxy config_invalid engine=%s missing=%s',
            $engine,
            implode(',', $missing)
        ));
        return null;
    }
    return $config;
}

function build_routes($engine) {
    // Недоступный движок не строит маршрутов вообще: цепочка идёт дальше,
    // не тратя ни секунды на сеть.
    if (engine_inactive($engine)) {
        error_log(sprintf('ai_proxy engine_inactive engine=%s', $engine));
        return array();
    }
    $config = engine_config($engine);
    if ($config === null) {
        return array();
    }
    $providers = array();
    if (isset($config['providers']) && is_array($config['providers']) && !empty($config['providers'])) {
        $providers = $config['providers'];
    } else {
        $providers[] = array(
            'url' => $config['url'],
            'key' => $config['key'],
            'models' => array($config['model']),
            // num_ctx пробрасываем дальше: движок один, но маршрутом на шаге
            // opencode может оказаться именно он, и лимит контекста обязан
            // уйти с этим маршрутом, а не с именем движка.
            'num_ctx' => isset($config['num_ctx']) ? $config['num_ctx'] : null,
        );
    }

    $routes = array();
    // Сколько провайдеров пропущено из-за паузы, а не по другой причине.
    // Различение нужно для аварийного перебора в конце функции: он существует
    // на случай битого состояния, и пропуск по паузе — не битое состояние.
    $skippedCooling = 0;
    foreach ($providers as $p) {
        if (!isset($p['url'], $p['key']) || $p['url'] === '' || $p['key'] === '') {
            continue;
        }
        $models = array();
        if (isset($p['models']) && is_array($p['models']) && !empty($p['models'])) {
            $models = $p['models'];
        } elseif (isset($p['model']) && $p['model'] !== '') {
            $models = array($p['model']);
        }
        if (empty($models)) {
            continue;
        }
        $host = parse_url($p['url'], PHP_URL_HOST);
        $needsSession = (strpos((string)$host, 'opencode') !== false);
        // Метка канала для клиента: 'primary' - основной провайдер, 'fallback' -
        // резервный. Это не имя провайдера и не модель, поэтому утечки в ответе
        // не происходит: тело по-прежнему пересобирается, model отбрасывается.
        // Нужно приложению, чтобы показать пользователю, каким каналом пришёл
        // результат. Значение - из закрытого списка, не из пользовательского
        // ввода, поэтому в заголовок попасть произвольная строка не может.
        $label = isset($p['label']) ? (string)$p['label'] : 'primary';
        if ($label !== 'fallback' && $label !== 'primary') {
            $label = 'primary';
        }
        // Цепочкой моделей одного провайдера идём только если провайдер не на
        // паузе. Пауза на провайдера, а не на модель: если хост лежит, то лежат
        // все его модели, и перебирать их бессмысленно - это и есть те самые
        // лишние таймауты.
        $cooling = false;
        provider_in_cooldown($host, $cooling);
        // Провайдер на паузе и провайдер всего один: идти к нему нельзя, иначе
        // пауза не сэкономит ничего. У боевых движков провайдер ровно один, и
        // прежнее array($models[0]) для них было полным маршрутом — то есть
        // размыкатель на паузе не срабатывал ни разу. Теперь цепочка пуста, и
        // клиент получает быстрый 503 и уходит на следующий шаг сам.
        //
        // У легаси-движка external провайдеров два, там поведение прежнее:
        // первый упавший не вычеркивается, цепочку до конца перебирают.
        if ($cooling && count($providers) === 1) {
            $skippedCooling++;
            error_log(sprintf(
                'ai_proxy provider_cooling_skip engine=%s host=%s cooldown=%d',
                $engine,
                $host,
                PROVIDER_COOLDOWN
            ));
            continue;
        }
        $models = $cooling ? array($models[0]) : $models;
        foreach ($models as $m) {
            $routes[] = array(
                'url' => upstream_chat_completions_url($p['url']),
                'key' => $p['key'],
                'model' => (string)$m,
                'host' => (string)$host,
                'label' => $label,
                'engine' => (string)$engine,
                'needs_session' => $needsSession,
                // num_ctx едет с маршрутом, а не берётся из $engine: на шаге
                // opencode маршрутом может оказаться локальный провайдер, и
                // его лимит контекста должен уйти вместе с ним. Поле необяза-
                // тельное — у облачных провайдеров его нет.
                'num_ctx' => isset($p['num_ctx']) && $p['num_ctx'] !== ''
                    ? (int)$p['num_ctx']
                    : null,
                // Свой бюджет маршрута вместо дележа route_timeout: два
                // маршрута в цепочке не должны делить 28 с пополам, от этого
                // opencode historically срезался на 12 с при живых 20-26.
                'budget' => (int)engine_timeout($engine),
            );
        }
    }
    // Если на паузе оказались все провайдеры, цепочка пуста и клиент получит
    // 503, хотя на самом деле все могли ожить. В этом случае снимаем паузу с
    // первого и пробуем его: лучше один таймаут, чем ложное «всё недоступно».
    //
    // Исключение — когда пустота вызвана самой паузой (skippedCooling). Тогда
    // состояние не битое, оно говорит ровно то, что должно: провайдер лежит.
    // Пробник здесь означал бы ровно то, от чего пауза и защищает, — полный
    // таймаут на упавшем хосте, только теперь гарантированно для каждого
    // запроса в окне паузы, а не для первого. Метку в лог кладём, иначе
    // «всё недоступно» и «лежит провайдер» выглядят в логе одинаково.
    if (empty($routes) && !empty($providers) && $skippedCooling === 0) {
        $first = $providers[0];
        if (isset($first['url'], $first['key']) && $first['url'] !== '' && $first['key'] !== '') {
            provider_mark_success(parse_url($first['url'], PHP_URL_HOST));
            $host = parse_url($first['url'], PHP_URL_HOST);
            $models = (isset($first['models']) && is_array($first['models']) && $first['models'])
                ? $first['models']
                : array(isset($first['model']) ? $first['model'] : '');
            $routes[] = array(
                'url' => upstream_chat_completions_url($first['url']),
                'key' => $first['key'],
                'model' => (string)$models[0],
                'host' => (string)$host,
                'label' => 'primary',
                'engine' => (string)$engine,
                'needs_session' => (strpos((string)$host, 'opencode') !== false),
                'num_ctx' => isset($first['num_ctx']) && $first['num_ctx'] !== ''
                    ? (int)$first['num_ctx']
                    : null,
                'budget' => (int)engine_timeout($engine),
            );
            error_log('ai_proxy all_providers_cooling forced_probe host=' . $host);
        }
    }
    return $routes;
}

/**
 * Бюджет на одну попытку. Клиент ждёт 30 секунд, поэтому суммарно цепочка
 * обязана в них уложиться: первый маршрут получает большую часть, каждый
 * следующий - тем меньше, а последнему оставляем хотя бы пару секунд на то,
 * чтобы успеть вернуть клиенту хоть какой-то внятный статус.
 */
function route_timeout($attempt, $total) {
    if ($total <= 1) {
        return UPSTREAM_TIMEOUT;
    }
    // Клиент ждёт responseTimeout (30с), поэтому сумма таймаутов всей цепочки
    // обязана в него уложиться с запасом на передачу ответа.
    //
    // Доли не равные: основной провайдер отвечает чаще и медленнее (замеры
    // opencode давали от 4 до 23 секунд), поэтому он получает двойную долю.
    // Резервные делят остаток поровну.
    //
    // Раньше здесь вычиталась доля из полного UPSTREAM_TIMEOUT: первая
    // попытка забирала все 28 секунд, а на трёх маршрутах сумма доходила до
    // 69с. Клиент отваливался по своему таймауту, не дождавшись второго
    // провайдера, - цепочка не работала вовсе.
    $budget = (int)floor(UPSTREAM_TIMEOUT * 0.9);
    if ($attempt <= 1) {
        $share = (int)floor($budget * 2 / ($total + 1));
    } else {
        $share = (int)floor($budget / ($total + 1));
    }
    if ($share < 2) {
        $share = 2;
    }
    return $share;
}

/**
 * Бюджет движка с одним маршрутом. Неизвестный движок — полный
 * UPSTREAM_TIMEOUT: лучше лишний шанс, чем ложное «всё недоступно».
 */
function engine_timeout($engine) {
    if (isset(ENGINE_TIMEOUT[$engine])) {
        return (int)ENGINE_TIMEOUT[$engine];
    }
    return UPSTREAM_TIMEOUT;
}

function client_ip() {
    $remote = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
    $fromCf = isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? trim((string)$_SERVER['HTTP_CF_CONNECTING_IP']) : '';

    if ($fromCf !== '' && $remote !== '' && ip_in_ranges($remote, CF_EDGE_RANGES)) {
        $candidate = @inet_pton($fromCf);
        if ($candidate !== false) {
            return $fromCf;
        }
    }
    // Запрос пришёл не из Cloudflare: доверяем заголовку нельзя, берём сокет.
    return ($remote === '') ? '0.0.0.0' : $remote;
}

// Случайная hex-строка фиксированной длины без внешних библиотек.
// openssl_random_pseudo_bytes есть с PHP 5.3; если расширения нет — mt_rand.
// Значение не выводится из входа запроса: ни из IP, ни из заголовков, ни из тела.
function random_hex($chars) {
    $hex = '';
    if (function_exists('openssl_random_pseudo_bytes')) {
        $raw = @openssl_random_pseudo_bytes($chars, $strong);
        if (is_string($raw) && strlen($raw) === $chars) {
            $hex = bin2hex($raw);
        }
    }
    if ($hex === '') {
        for ($i = 0; $i < $chars * 2; $i++) {
            $hex .= dechex(mt_rand(0, 15));
        }
    }
    return $hex;
}

// Идентификатор сессии для заголовка x-opencode-session. Формат 8-4-4-4-12,
// то есть UUID-подобный. Значение, присланное клиентом, берётся как есть,
// но только если оно выглядит как токен: иначе генерируем своё. Проверка
// нужна ещё и потому, что строка уходит в CURLOPT_HTTPHEADER дословно, то есть
// это единственное место, где вход клиента попадает в исходящий заголовок.
function opencode_session_id($incoming) {
    $given = isset($incoming) ? trim((string)$incoming) : '';
    if ($given !== '' && preg_match('/^[A-Za-z0-9._-]{1,128}$/', $given)) {
        return $given;
    }
    $hex = random_hex(16);
    return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4)
        . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
}

// Нормализация базы провайдера в эндпоинт chat/completions. В ai-config.php
// лежит БАЗА ('https://aislave.win', 'https://opencode.ai/zen/go'), а не путь:
// приложение дописывает его само в AiShared.chatCompletionsUrl
// (parsed_receipt.dart:333-337) — полный эндпоинт как есть, /v1 плюс
// /chat/completions, иначе плюс /v1/chat/completions. Без этого запрос ушёл бы
// на корень провайдера, тот ответил бы 404, клиент превратил бы его в badModel,
// а badModel не ретраится — и цепочка фолбэка на этом оборвалась бы.
// ОБЯЗАНА ОСТАВАТЬСЯ В СОГЛАСИИ С chatCompletionsUrl приложения: при смене
// правил там править и здесь. substr+strlen вместо str_ends_with — тот
// доступен только с PHP 8.0. Хвостовой слэш срезаем, чтобы не склеить '//'.
function upstream_chat_completions_url($base) {
    $url = rtrim((string)$base, '/');
    if ($url === '') {
        return $url;
    }
    $full = '/chat/completions';
    $v1 = '/v1';
    if (substr($url, -strlen($full)) === $full) {
        return $url;
    }
    if (substr($url, -strlen($v1)) === $v1) {
        return $url . $full;
    }
    return $url . $v1 . $full;
}

// Токен-бакет на фиксированном окне в минуту. Состояние вне веб-рута, чтобы
// не отдаваться по HTTP. Не смогли завести счёт — не блокируем пользователя.
// Каждый отказ пишется в лог: иначе мёртвый лимит неотличим от рабочего и
// сайт молча принимает неограниченное число платных запросов. В лог уходит
// только имя причины, без IP, без счётчиков и без значений состояния.
// Суффикс $token приходит из rate_state_suffix() и постоянен между запросами —
// иначе каждый запрос получил бы свой пустой каталог и счётчик никогда не рос.
function rate_limited($ip, $token) {
    $dir = rtrim(sys_get_temp_dir(), '/\\') . '/garant-ai-rate-' . $token;
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        error_log('ai_proxy rate_limit_unavailable reason=mkdir');
        return false;
    }
    $file = $dir . '/' . substr(sha1($ip), 0, 16) . '.json';
    // Чтение, проверка и запись идут под одной эксклюзивной блокировкой.
    // Раньше блокировка была только на записи, а чтение и проверка шли вне неё:
    // N одновременных запросов с одного IP читали один и тот же count, все
    // проходили и все писали count+1, то есть пачка считалась за один запрос и
    // потолок обходился полностью. Режим 'c+' создаёт файл, если его нет, и
    // не обрезает существующий, поэтому исчезает и гонка на создании.
    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        error_log('ai_proxy rate_limit_unavailable reason=fopen');
        return false;
    }
    if (!@flock($fh, LOCK_EX)) {
        fclose($fh);
        error_log('ai_proxy rate_limit_unavailable reason=flock');
        return false;
    }
    // Уборка мусора — под той же блокировкой и до чтения состояния, но уже после
    // успешного открытия счётчика: на отказных путях выше каталога может ещё
    // не быть, и убирать там нечего.
    rate_cleanup_stale($dir);
    $raw = stream_get_contents($fh);
    $state = json_decode((string)$raw, true);
    $now = time();
    $start = $now;
    $count = 0;
    if (is_array($state)) {
        $start = isset($state['start']) ? (int)$state['start'] : $now;
        $count = isset($state['count']) ? (int)$state['count'] : 0;
    }
    if ($now - $start >= 60) {
        $start = $now;
        $count = 0;
    }
    if ($count >= RATE_LIMIT_PER_MINUTE) {
        flock($fh, LOCK_UN);
        fclose($fh);
        return true;
    }
    rewind($fh);
    ftruncate($fh, 0);
    $next = json_encode(array('start' => $start, 'count' => $count + 1));
    $written = is_string($next) ? @fwrite($fh, $next) : false;
    if (!is_int($written) || $written < strlen($next)) {
        // Частичная запись оставляет битое состояние, но блокировать нельзя:
        // ложный 429 хуже пропуска. Дальше json_decode вернёт не-массив и счётчик
        // начнёт окно заново.
        error_log('ai_proxy rate_limit_unavailable reason=write');
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return false;
}

// Уборка старых файлов счётчиков. Имя файла — это sha1 адреса, а за одним
// публичным IP мобильного оператора сидят сотни абонентов, и IPv6 выдаёт
// временные адреса каждому новому соединению: на шэред-хостинге это тысячи
// файлов в час, и иноды кончаются. Состояние в них живёт меньше минуты по
// определению — новое окно стартует с нуля, — поэтому в каталоге счётчиков
// нечего терять и всё старше RATE_STALE_AFTER можно удалить.
//
// Сама уборка не чаще раза в минуту: обход каталога на каждый запрос стоит
// дороже, чем он экономит. Время последней уборки лежит в отдельном файле-метке
// в том же каталоге. В отличие от суффикса state-каталога такая метка уместна
// на диске: в ней лежит только время, секрета она не содержит, а имя
// предсказуемо и безобидно. Всё под @ — чужая ошибка прав или чтения не должна
// ломать запрос, тем более что сам лимит при отказе уборки остаётся целым.
// Метку '.gc-at' точка и расширение без .json отсекают от удаления: файлы
// счётчиков всегда заканчиваются на '.json'.
function rate_cleanup_stale($dir) {
    $stamp_file = $dir . '/.gc-at';
    $now = time();
    $raw = @file_get_contents($stamp_file);
    if (is_string($raw)) {
        $last = (int)$raw;
        if ($last > 0 && ($now - $last) < 60) {
            return;
        }
    }
    // Метка времени обновляется до обхода: если обход не удастся, повтор
    // попробует через минуту, а не на каждом запросе.
    @file_put_contents($stamp_file, (string)$now);
    $names = @scandir($dir);
    if (!is_array($names)) {
        return;
    }
    foreach ($names as $name) {
        if (substr($name, -5) !== '.json') {
            continue;
        }
        $path = $dir . '/' . $name;
        if (!@is_file($path)) {
            continue;
        }
        $mtime = @filemtime($path);
        if ($mtime === false || ($now - $mtime) < RATE_STALE_AFTER) {
            continue;
        }
        @unlink($path);
    }
}

// Суффикс каталога состояния счётчика. Ровно 16 символов из [0-9a-f]: ни
// разделителя пути, ни печатаемого символа, ни чего-либо, что можно вывести из
// IP, заголовков или тела запроса. Считается на каждый запрос, но ничего не
// хранит: hash_hmac есть с PHP 5.1.2, substr — всегда, то есть и на 5.6, и на
// 8.1 выходит одно и то же.
//
// Стабильность и неугадываемость тут не противоречие, а два требования к
// одному значению. Стабильность даёт то, что значение — чистая функция от
// seed, а не свежая случайность на запрос: считай его заново — каждый запрос
// получает новый пустой каталог, счёт в нём всегда 0, порог 30 не срабатывает
// никогда, а в общем tmpdir копится каталог на запрос (43 200 в сутки с
// одного адреса).
//
// seed — ключ внешнего провайдера из ai-config.php, иначе __FILE__. Гадать имя
// каталога по сути бессмысленно: соседний аккаунт на шэре, умеющий писать в
// общий tmpdir, умеет и прочитать docroot, где конфиг лежит открытым, — и сам
// ключ тоже становится известен. Негадаемость тут не нужна: атакующий, знающий
// исходные данные, всё равно заведёт свой счёт, но испортить наш не сможет.
// Обменяли файл-метку с его гонкой двух процессов и постоянным риском «метка
// битая, счётчик молча не заводится навсегда» на вычисление без единого
// обращения к диску.
//
// Путей отказа нет: функция не пишет, не читает и не создаёт каталогов, то
// есть не может зафейлить. Поэтому здесь исчезают и fail-open, и запись в лог
// с reason=suffix, и проверка непустоты — вызывающий получает готовую строку
// всегда, а пустой суффикс как выходное значение больше невозможен.
function rate_state_suffix() {
    $seed = isset(AI_PROXY_CONFIG['external']['key'])
        ? (string)AI_PROXY_CONFIG['external']['key']
        : __FILE__;
    return substr(hash_hmac('sha256', 'garant-ai-rate-v1', $seed), 0, 16);
}

$path = parse_url(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH);
if (!is_string($path)) {
    $path = '';
}

if ($path === '/ai/healthz') {
    // Спека говорит GET. На любой другой метод — общий 405, как и у движков.
    if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'GET') {
        header('Allow: GET');
        log_reject('healthz', $path, 405, 'method_not_allowed');
        respond_json(405, array('error' => 'method_not_allowed'));
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo "ok\n";
    exit;
}

// Отметка «локальный движок жив» от ПК владельца.
//
// Кто зовёт: задача автозапуска на его машине шлёт POST один раз при старте и
// дальше по таймеру. Что делает: обновляет время последнего подтверждения, по
// которому LOCAL_ALIVE_TTL решает, считать ли движок живым.
//
// Ответ всегда 200 с текущим остатком TTL, даже если запись не удалась:
// выключенный ПК ничего не спрашивает, и молчание об ошибке записи только
// заставит владельца гадать. Ошибка видна в error_log, а клиент приложения
// этот путь не зовёт вовсе.
if ($path === '/ai/local-alive') {
    if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Allow: POST');
        log_reject('local', $path, 405, 'method_not_allowed');
        respond_json(405, array('error' => 'method_not_allowed'));
    }
    $stored = local_mark_alive();
    if (!$stored) {
        error_log('ai_proxy local_alive_write_failed');
    }
    respond_json(200, array('alive' => true, 'ttl' => LOCAL_ALIVE_TTL));
}

$engines = array(
    '/ai/local/v1/chat/completions' => 'local',
    '/ai/v1/chat/completions' => 'chain',
);
if (!isset($engines[$path])) {
    // Engine неизвестен: пути до движка в коде ещё не было, а факт запроса
    // мимо обоих движков логировать надо — иначе 404 неотличим от тишины.
    log_reject('', $path, 404, 'not_found');
    respond_json(404, array('error' => 'not_found'));
}
$engine = $engines[$path];

// Недоступный движок отбивается до чтения тела: клиент уже прислал несколько
// сотен килобайт фотографии, и читать их впустую незачем. Без этого проверка
// ниже, в build_routes, дала бы тот же 503, но после stream_get_contents — то
// есть после лимита памяти и лимита скорости по IP. Лимит здесь тоже не
// тратим: один недоступный шаг не должен стоить места в окне минуты.
if (engine_inactive($engine)) {
    log_reject($engine, $path, 503, 'engine_inactive');
    respond_json(503, array('error' => 'upstream_unavailable'));
}

if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    log_reject($engine, $path, 405, 'method_not_allowed');
    respond_json(405, array('error' => 'method_not_allowed'));
}

// Суффикс каталога состояния счётчика. sys_get_temp_dir() общий, а имя
// '/garant-ai-rate' предсказуемо: чужой аккаунт на том же шаред-хостинге мог бы
// заранее создать каталог или подсунуть вместо него симлинк. Суффикс не даёт
// такого, и при этом переживает запросы — иначе счёт обнулялся бы на каждом.
// Чистая функция, путей отказа нет: проверки на непустоту здесь больше не
// нужны, каталог с пустым суффиксом не создаётся тем более.
$rate_token = rate_state_suffix();

$ip = client_ip();
if (rate_limited($ip, $rate_token)) {
    header('Retry-After: 60');
    log_reject($engine, $path, 429, 'rate_limited');
    respond_json(429, array('error' => 'rate_limited'));
}

// Проверяем Content-Length до чтения: post_max_size на хостинге 128M, а лимит
// памяти 512M, и PHP затащил бы в память произвольный мусор.
$length = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
if ($length > MAX_BODY_BYTES) {
    log_reject($engine, $path, 413, 'payload_too_large');
    respond_json(413, array('error' => 'payload_too_large'));
}
// Через fopen + stream_get_contents, а не file_get_contents с $context=null:
// на 8.1 null вместо ресурса даёт E_DEPRECATED на каждый запрос, а log_errors
// в файле включён принудительно — то есть в лог шёл бы мусор на каждый чих.
$in = @fopen('php://input', 'r');
if ($in === false) {
    log_reject($engine, $path, 413, 'body_unreadable');
    respond_json(413, array('error' => 'payload_too_large'));
}
// MAX_BODY_BYTES + 1, а не ровно лимит: лишний байт нужен, чтобы отличить
// тело ровно в лимит от тела длиннее лимита.
$raw = stream_get_contents($in, MAX_BODY_BYTES + 1);
fclose($in);
if ($raw === false || strlen($raw) > MAX_BODY_BYTES) {
    log_reject($engine, $path, 413, 'payload_too_large');
    respond_json(413, array('error' => 'payload_too_large'));
}

$incoming = json_decode($raw, true);
if (!is_array($incoming) || !isset($incoming['messages'])
    || !is_array($incoming['messages']) || count($incoming['messages']) === 0) {
    log_reject($engine, $path, 400, 'messages_required');
    respond_json(400, array('error' => 'messages_required'));
}

// Цепочка движков единого пути: прокси сам обходит local -> opencode ->
// openrouter. Отдельный путь local остаётся для дебага приложения.
$chainEngines = ($engine === 'chain')
    ? array('local', 'opencode', 'openrouter')
    : array($engine);
// Тело пересобирается: messages берём у клиента (там промпт и фото), а модель
// и лимиты — свои, по каждому маршруту. Клиент не может подсунуть дорогую
// модель или поднять max_tokens. Заголовок Authorization клиента не
// переносится: свой ставим ниже, по маршруту.
$outgoing = array(
    'messages' => $incoming['messages'],
    'temperature' => 0.1,
    'max_tokens' => 4096,
);

// Маршруты движков цепочки, по порядку. Недоступный движок маршрутов не
// строит: build_routes возвращает пусто, и цепочка идёт дальше, не тратя
// ни секунды на сеть.
$routes = array();
foreach ($chainEngines as $subEngine) {
    foreach (build_routes($subEngine) as $route) {
        $routes[] = $route;
    }
}
if (empty($routes)) {
    log_reject($engine, $path, 503, 'no_routes');
    respond_json(503, array('error' => 'upstream_unavailable'));
}

$body = false;
$status = 0;
$ms = 0;
$tried = 0;
$lastStatus = 0;
$error = '';
// Метка канала, который ответил: 'primary' или 'fallback'. Отдаётся клиенту
// заголовком, а не телом, чтобы не раскрывать провайдера и модель.
$servedLabel = '';
// Движок, ответивший на запрос цепочки: local, opencode или openrouter.
// Отдаётся клиенту заголовком X-AI-Engine — приложение по нему различает
// движки в логах.
$servedEngine = '';
// Хосты, уже провалившиеся в этом проходе: их модели больше не опрашиваем.
$seenFailedHosts = array();

foreach ($routes as $route) {
    if (isset($seenFailedHosts[$route['host']])) {
        continue;
    }
    $tried++;
    $outgoing['model'] = $route['model'];
    // num_ctx едет с маршрутом, а не выводится из $engine: маршрутом на шаге
    // opencode может быть локальный провайдер. Ставим и убираем явно, иначе
    // лимит предыдущего маршрута утечёт в следующий — локальный контекст,
    // подставленный облачному, или наоборот.
    if (isset($route['num_ctx']) && $route['num_ctx'] !== null) {
        $outgoing['num_ctx'] = $route['num_ctx'];
        $outgoing['options'] = array('num_ctx' => $route['num_ctx']);
    } else {
        unset($outgoing['num_ctx'], $outgoing['options']);
    }
    $payload = json_encode($outgoing);
    if (!is_string($payload) || $payload === '') {
        log_reject($engine, $path, 400, 'payload_not_encodable');
        respond_json(400, array('error' => 'payload_not_encodable'));
    }

$headers = array(
    'Authorization: Bearer ' . $route['key'],
    'Content-Type: application/json',
    'User-Agent: garant-proxy/1.0',
);
    // x-opencode-session нужен только провайдерам семейства opencode: без него
    // OpenCode Go отвечает 400 MissingSessionID. OpenRouter такого заголовка не
    // требует, а лишний ему не вредит, но неразборчиво слать его всем подряд.
    if ($route['needs_session']) {
        $incoming_session = isset($_SERVER['HTTP_X_OPENCODE_SESSION'])
            ? $_SERVER['HTTP_X_OPENCODE_SESSION']
            : '';
        $headers[] = 'x-opencode-session: ' . opencode_session_id($incoming_session);
    }

    $ch = curl_init($route['url']);
    curl_setopt_array($ch, array(
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_RETURNTRANSFER => true,
        // Свой бюджет маршрута. Делёж route_timeout больше не применяется ни
        // к одному боевому движку: он резал opencode до 12 с при живых 20-26,
        // а с приписыванием локалки первым маршрутом стало бы ещё хуже. Легаси-
        // движок external с тремя маршрутами остаётся на старом дележаке.
        CURLOPT_TIMEOUT => (count($routes) === 1 && !isset($route['budget']))
            ? engine_timeout($engine)
            : (isset($route['budget'])
                ? (int)$route['budget']
                : route_timeout($tried, count($routes))),
        CURLOPT_CONNECTTIMEOUT => CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER => $headers,
    ));
    $started = microtime(true);
    $body = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    // Код нужен, чтобы отличить «хост умирал долго» (таймаут всего бюджета)
    // от «хост мёртв» (отказ/DNS/таймаут соединения): текст curl_error зависит
    // от локали, а число стабильно.
    $errno = curl_errno($ch);
    curl_close($ch);
    $ms = (int)round((microtime(true) - $started) * 1000);

    error_log(sprintf(
        'ai_proxy try=%d/%d engine=%s model=%s host=%s ip=%s status=%d ms=%d bytes=%d err=%s',
        $tried,
        count($routes),
        $engine,
        $route['model'],
        $route['host'],
        substr(sha1($ip), 0, 12),
        $status,
        $ms,
        ($body === false) ? 0 : strlen($body),
        $error === '' ? '-' : $error
    ));

    // Не чаще одного раза на провайдера за проход: первая неудача ставит его на
    // паузу, и следующие его модели в этом же проходе опрашивать нельзя,
    // иначе цепочка съест весь бюджет на один лежащий хост.
    $hostFailed = isset($seenFailedHosts[$route['host']]) ? $seenFailedHosts[$route['host']] : false;

    // Успех - и дальше не идём. 200 означает, что цепочка моделей этого
    // провайдера уже отдала лучшее, что могла. Паузу снимаем: провайдер жив.
    if ($body !== false && $status === 200) {
        $servedLabel = $route['label'];
        $servedEngine = isset($route['engine']) ? (string)$route['engine'] : '';
        provider_mark_success($route['host']);
        break;
    }
    $lastStatus = $status;
    // 401/403 - это не «модель недоступна», а неверный ключ: остальные
    // маршруты на том же ключе (тот же хост) провалятся так же, поэтому их
    // в этом проходе больше не опрашиваем. Цепочка при этом продолжается:
    // у других движков свои ключи, и им этот провал нипочём.
    if ($status === 401 || $status === 403) {
        $seenFailedHosts[$route['host']] = true;
        $body = false;
        $status = 0;
        continue;
    }
    // Недоступность хоста, а не конкретной модели: обрыв, 5xx,
    // пустой или нечитаемый ответ. Ставим провайдера на паузу, чтобы следующий
    // запрос ушёл к другому сразу, не повторяя оплаченный таймаут.
    //
    // Исключение — медленная локалка: движок принял соединение и жевал почти
    // весь свой бюджет, но не уложился. Хост при этом жив: мёртвый умер бы на
    // CONNECT_TIMEOUT или отказе сразу, не дотянув до конца бюджета. Чаще
    // всего это холодная модель, которая к следующему запросу уже прогрета, —
    // наказывать её паузой значит слать следующие запросы в медленный
    // opencode зря. Действует только на local: таймаут облака — признак
    // по-настоящему больного провайдера, там пауза остаётся.
    // 28 — CURLE_OPERATION_TIMEDOUT (PHP не объявляет CURLE_*-константы).
    // Порог «почти весь бюджет»: бюджет local 13с, смерть соединения — 8с,
    // запас 2с на гранулярность замера.
    $routeEngine = isset($route['engine']) ? (string)$route['engine'] : '';
    $slowLocalTimeout = ($routeEngine === 'local')
        && $errno === 28
        && $ms >= (int)engine_timeout('local') * 1000 - 2000;
    if ($slowLocalTimeout) {
        error_log(sprintf(
            'ai_proxy local_slow_no_cooldown host=%s ms=%d',
            $route['host'],
            $ms
        ));
    }
    if (!$hostFailed && !$slowLocalTimeout && !in_array($status, array(400, 404, 422), true)) {
        $seenFailedHosts[$route['host']] = true;
        provider_mark_failure($route['host']);
        error_log(sprintf(
            'ai_proxy provider_cooling host=%s status=%d ms=%d cooldown=%d',
            $route['host'],
            $status,
            $ms,
            PROVIDER_COOLDOWN
        ));
    }
    $body = false;
    $status = 0;
}

// curl_init без проверки — фатал на каждом запросе, если расширения нет, и в
// логе остаётся одна строка PHP без внятного «чего» не хватило. Проверка
// превращает белый экран в диагностируемое состояние: в лог причина, клиенту
// 503, то есть тот же код, что у недоступного апстрима.
if (!function_exists('curl_init')) {
    log_reject($engine, $path, 503, 'curl_extension_missing');
    respond_json(503, array('error' => 'upstream_unavailable'));
}

if ($body === false || $status === 0) {
    respond_json(503, array('error' => 'upstream_unreachable'));
}

// 401/403 апстрима не показываем как есть: приложение прочитало бы это как
// «неверный ключ» про наш сервер, хотя со стороны пользователя всё верно.
// 503 переводится в «занято» и уводит цепочку на второй движок.
if ($status === 401 || $status === 403) {
    $status = 503;
}

// Дословно тело апстрима наружу не отдаётся никогда. На не-200 уходит свой
// JSON: в тексте ошибки провайдер печатает движок, модель и маскированный ключ
// («Incorrect API key provided: sk-…***…»), то есть утечку ключа в ослабленной
// форме плюс перебор по символам. На 200 тело тоже пересобирается: дословный
// ответ несёт model и system_fingerprint провайдера, то есть прямо говорит
// пользователю, какой движок сработал. Приложение из ответа читает только
// choices[0].message.content, поэтому наружу уходит ровно это и ничего больше.
// Лог выше ответа не касается: в нём остаются только статус, длительность и
// strlen($body), взятый до подмены.
http_response_code($status);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
// Метка канала, ответившего на 200. Приложение по ней различает основной и
// резервный провайдер и помечает результат. Значение - строго из
// ('primary','fallback'), то есть произвольная строка сюда не попадает.
if ($status === 200 && $servedLabel !== '') {
    header('X-AI-Channel: ' . $servedLabel);
}
// Движок, ответивший на запрос цепочки. Строго из закрытого списка, иначе
// заголовок не ставится вовсе: произвольная строка из конфига в ответ
// попасть не должна.
if (
    $status === 200 &&
    in_array($servedEngine, array('local', 'opencode', 'openrouter'), true)
) {
    header('X-AI-Engine: ' . $servedEngine);
}
if ($status === 200) {
    // Пустое тело при 200 — клиент тихо получил бы 'empty' с ретраем и
    // разжёг бы фолбэк по кругу. Это ошибка апстрима, а не клиента: 502.
    if (trim($body) === '') {
        respond_json(502, array('error' => 'upstream_empty'));
    }
    $decoded = json_decode($body, true);
    $content = null;
    if (is_array($decoded) && isset($decoded['choices'][0]['message']['content'])) {
        // content бывает строкой (text-only движок) и списком частей
        // (мультимодальные). Приложение умеет и то, и то, поэтому значение
        // переносим как есть; всё остальное — отбрасываем.
        $content = $decoded['choices'][0]['message']['content'];
    }
    // Разбор не удался или content нет — подменять тело своим нельзя: клиент
    // получил бы правдоподобный JSON без результата. 502 честнее.
    if (!is_string($content) && !is_array($content)) {
        respond_json(502, array('error' => 'upstream_malformed'));
    }
    $minimal = json_encode(
        array('choices' => array(array('message' => array('content' => $content)))),
        JSON_UNESCAPED_UNICODE
    );
    if (!is_string($minimal) || $minimal === '') {
        respond_json(502, array('error' => 'upstream_malformed'));
    }
    echo $minimal;
} else {
    echo json_encode(array('error' => 'upstream_unavailable'));
}
exit;

