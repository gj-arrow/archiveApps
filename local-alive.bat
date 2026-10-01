@echo off
REM Отметка «локальный движок жив» для прокси appcreatores.win.
REM Ставится в задачу автозапуска Windows: один раз при входе и по таймеру.
REM Прокси считает движок живым, пока отметка не протухла (TTL 15 минут),
REM и мгновенно пропускает шаг, если ПК выключен.

setlocal
set "URL=https://appcreatores.win/ai/local-alive"

REM curl есть в Windows 10 1803+ и в 11 из коробки. -s тихо, --max-time чтобы
REM задача не висела при отсутствии сети, код ответа не важен: даже при ошибке
REM метка просто не обновится и local выключится сам, что и нужно.
curl.exe -s -o NUL --max-time 10 -X POST "%URL%" >NUL 2>&1

exit /b 0