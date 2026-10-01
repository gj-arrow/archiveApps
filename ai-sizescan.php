<?php
/**
 * Замер: один и тот же снимок в разных размерах, по моделям.
 * Временный диагностический файл, после выяснения удалить.
 *
 * Рядом с ним должен лежать diag_check.jpg - настоящая фотография чека.
 * Открываете этот файл в браузере, получаете таблицу.
 */

declare(strict_types=1);

const TIMEOUT = 45;

$cfgPath = __DIR__ . '/ai-config.php';
if (!is_readable($cfgPath)) {
    header('Content-Type: text/plain; charset=utf-8');
    echo "нет ai-config.php рядом\n";
    exit(1);
}
$cfg = @include $cfgPath;
if (!is_array($cfg) || empty($cfg['external']['url'])) {
    header('Content-Type: text/plain; charset=utf-8');
    echo "в ai-config.php нет блока external с url\n";
    exit(1);
}
$base = rtrim((string) $cfg['external']['url'], '/');
// В конфиге адрес может быть как базой, так и уже полным эндпоинтом.
if (!str_ends_with($base, '/chat/completions')) {
    $base .= str_ends_with($base, '/v1') ? '/chat/completions' : '/v1/chat/completions';
}
$key = (string) ($cfg['external']['key'] ?? '');
if ($key === '') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "в ai-config.php у external пустой key\n";
    exit(1);
}

function sessionId(): string
{
    return sprintf(
        '%08x-%04x-4%03x-8%03x-%012x',
        mt_rand(0, 0xffffffff), mt_rand(0, 0xffff), mt_rand(0, 0xfff),
        mt_rand(0, 0xfff), mt_rand(0, 0xffffffffffff)
    );
}

function send(string $url, string $key, string $model, string $b64, string $mime): array
{
    $payload = json_encode([
        'model' => $model,
        'messages' => [[
            'role' => 'user',
            'content' => [
                ['type' => 'text', 'text' => 'Распознай гарантийный талон: магазин, дата, номер, товар, модель, серийный номер, срок гарантии в месяцах. Ответь только JSON.'],
                ['type' => 'image_url', 'image_url' => ['url' => 'data:' . $mime . ';base64,' . $b64]],
            ],
        ]],
        'max_tokens' => 1024,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $key,
            'Content-Type: application/json',
            'Accept: application/json',
            'x-opencode-session: ' . sessionId(),
        ],
        CURLOPT_TIMEOUT => TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => 10,
    ]);
    $t0 = microtime(true);
    $body = curl_exec($ch);
    $ms = (int) round((microtime(true) - $t0) * 1000);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    $text = '';
    if (is_string($body) && $code === 200) {
        $j = json_decode($body, true);
        $text = trim((string) ($j['choices'][0]['message']['content'] ?? ''));
    }
    return [
        'code' => $code, 'ms' => $ms, 'text' => $text,
        'errno' => $errno, 'err' => $err,
        'kb' => is_string($body) ? (int) round(strlen($body) / 1024) : 0,
    ];
}

header('Content-Type: text/plain; charset=utf-8');

if (!function_exists('imagecreatetruecolor')) {
    echo "на хостинге нет GD\n";
    exit(1);
}

$src = __DIR__ . '/diag_check.jpg';
if (!is_readable($src)) {
    echo "Положите рядом фотографию чека под именем diag_check.jpg и обновите страницу.\n";
    exit(1);
}
$img = @imagecreatefromjpeg($src);
if (!$img) {
    echo "не читается diag_check.jpg\n";
    exit(1);
}
$w0 = imagesx($img);
$h0 = imagesy($img);
echo "адрес провайдера: $base\n";
echo "исходник: {$w0}x{$h0}, " . round(filesize($src) / 1024) . " КБ\n\n";

// Модели, которые провайдер готов отдать
$models = [];
$modelsUrl = substr($base, 0, -strlen('/chat/completions')) . '/models';
$ch = curl_init($modelsUrl);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $key],
    CURLOPT_TIMEOUT => 15,
]);
$raw = curl_exec($ch);
$mc = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
$merr = curl_error($ch);
curl_close($ch);
if (is_string($raw) && $mc === 200) {
    foreach ((array) (json_decode($raw, true)['data'] ?? []) as $m) {
        if (!empty($m['id'])) {
            $models[] = (string) $m['id'];
        }
    }
}
if (!$models) {
    $models = ['glm-5.3-flash'];
    echo "список моделей не пришёл (код $mc" . ($merr ? ", $merr" : '') . "), беру glm-5.3-flash\n\n";
} else {
    echo "моделей у провайдера: " . count($models) . "\n\n";
}
// Модель задаётся в адресе: ?model=glm-5.3-flash&size=640
// По умолчанию берём именно ту, что прописана в ai-config.php: первые модели
// из /models у этого шлюза картинки не понимают.
$wantModel = (string) ($_GET['model'] ?? '');
if ($wantModel === '') {
    $wantModel = (string) ($cfg['external']['model'] ?? 'glm-5.3-flash');
}
if (!in_array($wantModel, $models, true)) {
    $models[] = $wantModel;
    echo "модели $wantModel нет в списке провайдера, пробуем всё равно\n";
}
$models = [$wantModel];

// Только уменьшение. Апскейл не даёт новой информации, только раздувает payload.
$sizes = [1600, 1280, 1024, 800, 640, 480];
// Лимит времени на хостинге не даёт прогнать всё за один заход, поэтому
// по умолчанию меряем один размер, остальные - через ?size= в адресе.
$only = isset($_GET['size']) ? (int) $_GET['size'] : 0;
if ($only > 0) {
    $sizes = [$only];
}
$variants = [];
foreach ($sizes as $s) {
    if ($s >= $w0) {
        continue;
    }
    $sh = (int) round($h0 * ($s / $w0));
    $t = imagecreatetruecolor($s, $sh);
    imagecopyresampled($t, $img, 0, 0, 0, 0, $s, $sh, $w0, $h0);
    ob_start();
    imagejpeg($t, null, 82);
    $jpeg = (string) ob_get_clean();
    imagedestroy($t);
    $variants[] = [
        'label' => $s . 'px',
        'b64' => base64_encode($jpeg),
        'kb' => (int) round(strlen($jpeg) / 1024),
    ];
}
imagedestroy($img);
if (!$variants) {
    echo "исходник уже меньше всех размеров под проверку, уменьшать нечего\n";
    exit(1);
}

printf("  %-8s %-14s %5s %9s %7s %7s  %s\n", 'размер', 'модель', 'код', 'всего', 'вес', 'ответ', 'начало');
echo "  " . str_repeat('-', 92) . "\n";

$lines = [];
foreach ($variants as $v) {
    foreach ($models as $m) {
        $r = send($base, $key, $m, $v['b64'], 'image/jpeg');
        $head = substr(preg_replace('/\s+/', ' ', $r['text']), 0, 30);
        printf(
            "  %-8s %-14s %5d %8dms %6dK %6d  %s\n",
            $v['label'], substr($m, 0, 14), $r['code'], $r['ms'], $v['kb'],
            (int) round(strlen($r['text']) / 2.6), $head
        );
        if ($r['errno']) {
            echo "      !!! curl({$r['errno']}): {$r['err']}\n";
        }
        $lines[] = $v['label'] . ' | ' . $m . ' | ' . $r['code'] . ' | ' . $r['ms'] . 'ms | ' . $v['kb'] . 'KB';
    }
}
@file_put_contents(__DIR__ . '/diag_result.txt', implode("\n", $lines));
echo "\nитог в diag_result.txt\n";
echo "потом удалить: ai-sizescan.php, ai-netdiag.php, diag_check.jpg, diag_result.txt\n";
