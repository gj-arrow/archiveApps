<?php
/**
 * Диагностика: где именно теряется время на пути к внешнему шлюзу.
 * Временный файл, после выяснения удалить.
 *
 * Показывает разбивку по стадиям, чтобы отличить медленный DNS,
 * медленное соединение, медленный TLS и медленный ответ провайдера.
 */

declare(strict_types=1);

$url = 'https://opencode.ai/zen/go/v1/chat/completions';

// Ключ внешнего провайдера берём из соседнего конфига, чтобы не светить тут.
$cfgPath = __DIR__ . '/ai-config.php';
$key = '';
if (is_readable($cfgPath)) {
    $cfg = @include $cfgPath;
    if (is_array($cfg)) {
        foreach ($cfg as $section) {
            if (is_array($section) && isset($section['key'])) {
                $key = (string) $section['key'];
            }
        }
    }
}
if ($key === '') {
    // Запасной путь: тот же env, что у генератора конфига.
    $envPath = dirname(__DIR__) . '/.env.local';
    if (is_readable($envPath)) {
        foreach (file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if (strpos($line, 'EXTERNAL_AI_API_KEY=') === 0) {
                $key = substr($line, strlen('EXTERNAL_AI_API_KEY='));
            }
        }
    }
}
if ($key === '') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "НЕТ КЛЮЧА: не смог прочитать ai-config.php или .env.local\n";
    exit(1);
}

/** Разбор /etc/resolv.conf: смотрим, не предлагает ли сервер IPv6. */
function hasV6Route(): array
{
    $out = ['v6_addr' => false, 'v6_route' => false, 'hosts' => false];
    if (is_readable('/etc/resolv.conf')) {
        $txt = (string) file_get_contents('/etc/resolv.conf');
        $out['v6_addr'] = (bool) preg_match('/^nameserver\s+([0-9a-f:]+)/mi', $txt, $m)
            && filter_var($m[1] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }
    // Есть ли вообще маршрут по умолчанию для v6
    @exec('ip -6 route show default 2>/dev/null', $r);
    $out['v6_route'] = !empty($r);
    // Поддерживает ли ядро v6 вообще
    $out['hosts'] = (bool) preg_match('/inet6/', (string) @file_get_contents('/proc/net/if_inet6'));
    return $out;
}

$payload = json_encode([
    'model' => 'glm-5.3-flash',
    'messages' => [['role' => 'user', 'content' => 'ok']],
    'max_tokens' => 8,
], JSON_UNESCAPED_UNICODE);

function probe(string $label, string $url, string $key, string $payload, array $opts): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $key,
            'Content-Type: application/json',
            'x-opencode-session: ' . sprintf(
                '%08x-%04x-4%03x-8%03x-%012x',
                mt_rand(0, 0xffffffff), mt_rand(0, 0xffff), mt_rand(0, 0xfff),
                mt_rand(0, 0xfff), mt_rand(0, 0xffffffffffff)
            ),
        ],
        CURLOPT_TIMEOUT => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
    ] + $opts);

    $started = microtime(true);
    $body = curl_exec($ch);
    $total = microtime(true) - $started;
    $info = curl_getinfo($ch);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    return [
        'label' => $label,
        'code' => $code,
        'ms' => (int) round($total * 1000),
        'dns' => (int) round(((float) ($info['namelookup_time'] ?? 0)) * 1000),
        'tcp' => (int) round(((float) ($info['connect_time'] ?? 0)) * 1000),
        'tls' => (int) round(((float) ($info['appconnect_time'] ?? 0)) * 1000),
        'first_byte' => (int) round(((float) ($info['starttransfer_time'] ?? 0)) * 1000),
        'ip' => $info['primary_ip'] ?? '',
        'http' => $info['http_version'] ?? '',
        'ssl' => $info['ssl_verify_result'] ?? '',
        'errno' => $errno,
        'err' => $err,
        'bytes' => is_string($body) ? strlen($body) : 0,
    ];
}

header('Content-Type: text/plain; charset=utf-8');
$net = hasV6Route();
echo "СЕТЬ\n";
echo "  IPv6-адрес у DNS: " . ($net['v6_addr'] ? 'да' : 'нет') . "\n";
echo "  маршрут v6:        " . ($net['v6_route'] ? 'да' : 'нет') . "\n";
echo "  v6-интерфейсы:     " . ($net['hosts'] ? 'да' : 'нет') . "\n";
echo "  curl:              " . (defined('LIBCURL_VERSION') ? LIBCURL_VERSION : '?') . "\n";
echo "  PHP:               " . PHP_VERSION . "\n\n";

echo "ЗАМЕРЫ\n";
$rows = [];
$rows[] = probe('обычно          ', $url, $key, $payload, []);
$rows[] = probe('только IPv4     ', $url, $key, $payload, [CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4]);
$rows[] = probe('только IPv6     ', $url, $key, $payload, [CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V6]);
$rows[] = probe('ещё раз, IPv4   ', $url, $key, $payload, [CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4]);

printf(
    "  %-16s %-4s %7s %6s %6s %6s %8s  %-22s %s\n",
    'вариант', 'код', 'всего', 'dns', 'tcp', 'tls', 'первый', 'ip', 'http'
);
foreach ($rows as $r) {
    printf(
        "  %-16s %-4d %6dms %5dms %5dms %5dms %7dms  %-22s %s\n",
        $r['label'], $r['code'], $r['ms'], $r['dns'], $r['tcp'], $r['tls'],
        $r['first_byte'], $r['ip'], $r['http']
    );
    if ($r['errno']) {
        echo "                     ошибка curl({$r['errno']}): {$r['err']}\n";
    }
}

echo "\nКАК ЧИТАТЬ\n";
echo "  если 'только IPv4' заметно быстрее 'обычно' - виноват IPv6,\n";
echo "     лечится одной строкой CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4 в proxy.php\n";
echo "  если 'первый байт' большой при мгновенном tls - отвечает медленно сам провайдер,\n";
echo "     и тут хостинг ни при чем, нужен VPS\n";
echo "  если tcp большой - проблема в сетевом маршруте хостинга\n";
