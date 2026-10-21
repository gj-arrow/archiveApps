<?php
// Приём формы страницы поддержки сайта (support.html).
// POST -> письмо на SUPPORT_TO. Ответ JSON, если запрос пришёл с заголовком
// X-Requested-With: fetch (так шлёт JS формы), иначе HTML-страница для
// браузера без JS.
//
// SUPPORT_FROM обязан быть на домене сайта: чужой домен в From не проходит
// SPF хостинга, и письма уезжают в спам. При переезде менять здесь.

@ini_set('display_errors', '0');
@ini_set('log_errors', '1');

// Получатель обращений. Меняется только здесь.
const SUPPORT_TO = 'appcreators.technolab@ya.ru';
// From и envelope-отправитель (-f) — на домене сайта (SPF).
const SUPPORT_FROM = 'no-reply@appcreatores.win';
const MAX_MESSAGE = 5000;
const RATE_LIMIT_PER_HOUR = 5;
const RATE_WINDOW = 3600;
const RATE_STALE_AFTER = 172800;

// Названия для темы письма: ключ формы => [RU, EN].
$SUPPORT_APPS = array(
    'videonyanya' => array('Видеоняня (BabyCamera Free)', 'BabyCamera Free (Video Nanny)'),
    'garant' => array('Архив гарантий (Warranty Archive)', 'Warranty Archive'),
    'health-diary' => array('Дневник здоровья (Health Diary)', 'Health Diary'),
    'other' => array('Общий вопрос', 'General question'),
);

// Сайт стоит за Cloudflare: REMOTE_ADDR — это edge, а не пользователь.
// CF-Connecting-IP доверяем только из диапазонов Cloudflare, иначе любой
// подставит заголовок и обойдёт лимит. Тот же список, что в proxy.php.
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

function client_ip() {
    $remote = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
    $fromCf = isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? trim((string)$_SERVER['HTTP_CF_CONNECTING_IP']) : '';
    if ($fromCf !== '' && $remote !== '' && ip_in_ranges($remote, CF_EDGE_RANGES)) {
        if (@inet_pton($fromCf) !== false) {
            return $fromCf;
        }
    }
    return ($remote === '') ? '0.0.0.0' : $remote;
}

// Каталог состояния лимита: вне веб-рута, имя с hmac-суффиксом, чтобы
// соседний аккаунт на шэред-хостинге не угадал каталог и не подсунул симлинк.
function support_state_dir() {
    $seed = SUPPORT_FROM . '|support-rate-v1';
    return rtrim(sys_get_temp_dir(), '/\\') . '/appcreatores-support-' . substr(hash_hmac('sha256', 'support', $seed), 0, 16);
}

// Фиксированное окно в час на IP. При любой внутренней ошибке — fail-open:
// неработающий лимит не должен запрещать живую почту.
function rate_limited($ip) {
    $dir = support_state_dir();
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        error_log('support rate_limit_unavailable reason=mkdir');
        return false;
    }
    $file = $dir . '/' . substr(sha1($ip), 0, 16) . '.json';
    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        error_log('support rate_limit_unavailable reason=fopen');
        return false;
    }
    if (!@flock($fh, LOCK_EX)) {
        fclose($fh);
        error_log('support rate_limit_unavailable reason=flock');
        return false;
    }
    rate_cleanup($dir);
    $raw = stream_get_contents($fh);
    $state = json_decode((string)$raw, true);
    $now = time();
    $start = $now;
    $count = 0;
    if (is_array($state)) {
        $start = isset($state['start']) ? (int)$state['start'] : $now;
        $count = isset($state['count']) ? (int)$state['count'] : 0;
    }
    if ($now - $start >= RATE_WINDOW) {
        $start = $now;
        $count = 0;
    }
    if ($count >= RATE_LIMIT_PER_HOUR) {
        flock($fh, LOCK_UN);
        fclose($fh);
        return true;
    }
    rewind($fh);
    ftruncate($fh, 0);
    $next = json_encode(array('start' => $start, 'count' => $count + 1));
    if (!is_string($next) || @fwrite($fh, $next) === false) {
        error_log('support rate_limit_unavailable reason=write');
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return false;
}

// Уборка старых файлов счётчиков не чаще раза в час: окно в час, а файл
// старше двух суток не прочитает ни один будущий запрос.
function rate_cleanup($dir) {
    $stamp = $dir . '/.gc-at';
    $now = time();
    $raw = @file_get_contents($stamp);
    if (is_string($raw) && (int)$raw > 0 && ($now - (int)$raw) < 3600) {
        return;
    }
    @file_put_contents($stamp, (string)$now);
    $names = @scandir($dir);
    if (!is_array($names)) {
        return;
    }
    foreach ($names as $name) {
        if (substr($name, -5) !== '.json') {
            continue;
        }
        $path = $dir . '/' . $name;
        $mtime = @filemtime($path);
        if ($mtime !== false && ($now - $mtime) > RATE_STALE_AFTER) {
            @unlink($path);
        }
    }
}

$wants_json = (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'fetch');

// Единая точка ответа. $error_key = null — успех.
function support_respond($status, $error_key, $lang, $wants_json) {
    $texts = array(
        'ok' => array(
            'ru' => 'Сообщение отправлено. Спасибо! Ответим на указанную почту.',
            'en' => 'Message sent. Thank you! We will reply to the address you provided.',
        ),
        'invalid' => array(
            'ru' => 'Проверьте поля формы: сообщение обязательно, email — если указан — должен быть корректным.',
            'en' => 'Check the form fields: the message is required, and the email — if given — must be valid.',
        ),
        'rate_limited' => array(
            'ru' => 'Слишком много отправок с вашего адреса. Попробуйте через час или напишите на appcreators.technolab@ya.ru.',
            'en' => 'Too many submissions from your address. Try again in an hour or write to appcreators.technolab@ya.ru.',
        ),
        'send_failed' => array(
            'ru' => 'Не удалось отправить письмо. Напишите нам напрямую: appcreators.technolab@ya.ru.',
            'en' => 'Could not send the message. Please write to us directly: appcreators.technolab@ya.ru.',
        ),
        'method' => array(
            'ru' => 'Неверный метод запроса.',
            'en' => 'Invalid request method.',
        ),
    );
    $key = ($error_key === null || $error_key === '') ? 'ok' : $error_key;
    $message = isset($texts[$key][$lang]) ? $texts[$key][$lang] : $texts[$key]['ru'];
    if ($wants_json) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode(array('ok' => $error_key === null, 'error' => $error_key, 'message' => $message), JSON_UNESCAPED_UNICODE);
        exit;
    }
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    $title = ($error_key === null)
        ? ($lang === 'en' ? 'Message sent' : 'Сообщение отправлено')
        : ($lang === 'en' ? 'Error' : 'Ошибка');
    $back = $lang === 'en' ? 'Back to the support page' : 'Назад на страницу поддержки';
    echo '<!DOCTYPE html><html lang="' . $lang . '"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="robots" content="noindex"><title>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . ' — AppCreatorsTechnoLab</title>'
        . '<style>body{margin:0;background:#0b1020;color:#eef1ff;font-family:Inter,system-ui,\'Segoe UI\',Roboto,Arial,sans-serif;line-height:1.6}'
        . 'main{max-width:640px;margin:0 auto;padding:48px 20px}h1{font-size:28px}a{color:#cfd6ff}</style></head><body><main>'
        . '<h1>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</h1>'
        . '<p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
        . '<p><a href="support.html">' . htmlspecialchars($back, ENT_QUOTES, 'UTF-8') . '</a></p>'
        . '</main></body></html>';
    exit;
}

if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    support_respond(405, 'method', 'ru', $wants_json);
}

$lang = (isset($_POST['lang']) && $_POST['lang'] === 'en') ? 'en' : 'ru';

// Honeypot: скрытое поле, которое заполняют только боты. Отвечаем как при
// успехе, письмо не шлём — бот не должен понять, что его отсекли. Лимит
// здесь не тратится намеренно.
if (isset($_POST['hp']) && trim((string)$_POST['hp']) !== '') {
    support_respond(200, null, $lang, $wants_json);
}

$app = isset($_POST['app']) ? (string)$_POST['app'] : '';
if (!isset($SUPPORT_APPS[$app])) {
    support_respond(400, 'invalid', $lang, $wants_json);
}

$email = isset($_POST['email']) ? trim((string)$_POST['email']) : '';
if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    support_respond(400, 'invalid', $lang, $wants_json);
}

$message = isset($_POST['message']) ? trim((string)$_POST['message']) : '';
$length = function_exists('mb_strlen') ? mb_strlen($message, 'UTF-8') : strlen($message);
if ($message === '' || $length > MAX_MESSAGE) {
    support_respond(400, 'invalid', $lang, $wants_json);
}

$ip = client_ip();
if (rate_limited($ip)) {
    header('Retry-After: ' . RATE_WINDOW);
    support_respond(429, 'rate_limited', $lang, $wants_json);
}

$app_names = $SUPPORT_APPS[$app];
$subject = '[Support] ' . $app_names[0] . ' — ' . date('d.m.Y H:i');
$body = "Новое обращение со страницы поддержки сайта\n\n"
    . "Приложение: {$app_names[0]} / {$app_names[1]}\n"
    . 'Email для ответа: ' . ($email !== '' ? $email : 'не указан') . "\n"
    . "Язык страницы: {$lang}\n"
    . 'Время: ' . date('d.m.Y H:i:s') . "\n"
    . "IP: {$ip}\n"
    . 'User-Agent: ' . (isset($_SERVER['HTTP_USER_AGENT']) ? substr((string)$_SERVER['HTTP_USER_AGENT'], 0, 300) : '-') . "\n\n"
    . "Сообщение:\n" . $message . "\n";

$headers = 'MIME-Version: 1.0' . "\r\n"
    . 'Content-Type: text/plain; charset=UTF-8' . "\r\n"
    . 'Content-Transfer-Encoding: 8bit' . "\r\n"
    . 'From: AppCreatorsTechnoLab <' . SUPPORT_FROM . '>' . "\r\n";
// Reply-To только из провалидированного filter_var адреса: переводы строк в
// заголовок попасть не могут.
if ($email !== '') {
    $headers .= 'Reply-To: ' . $email . "\r\n";
}
$subject_encoded = '=?UTF-8?B?' . base64_encode($subject) . '?=';

// На Windows (локальная отладка) 5-й аргумент mail() не поддерживается.
$params = (stripos(PHP_OS, 'WIN') === 0) ? '' : '-f' . SUPPORT_FROM;
$sent = ($params === '')
    ? @mail(SUPPORT_TO, $subject_encoded, $body, $headers)
    : @mail(SUPPORT_TO, $subject_encoded, $body, $headers, $params);

if (!$sent) {
    // IP в лог не пишем: хватает хэша, чтобы различать отправителей между
    // собой, а сам адрес — уже персональные данные.
    error_log('support send_failed app=' . substr($app, 0, 32) . ' ip_hash=' . substr(sha1($ip), 0, 16));
    support_respond(500, 'send_failed', $lang, $wants_json);
}

support_respond(200, null, $lang, $wants_json);
