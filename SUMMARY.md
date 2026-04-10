# PhishGuard — краткое summary проекта

## 1. Назначение системы

PhishGuard — сервис мониторинга почты и обнаружения фишинговых ссылок.
Система подключается к IMAP-ящикам, обрабатывает новые письма, извлекает URL, оценивает риск через ML-модуль и сохраняет результаты в PostgreSQL с отображением в веб-интерфейсе.

## 2. Архитектура

Компоненты:

- `backend` (Go)
  - REST API
  - воркер периодического опроса почты
  - бизнес-логика вердикта `safe/suspicious/phishing`
  - веб-консоль
- `ml` (Python/FastAPI)
  - endpoint инференса `/v1/predict/url`
  - гибридный пайплайн URL + text + fusion
- `db` (PostgreSQL)
  - хранение аккаунтов, писем, URL, результатов сканирования, ошибок

Интеграция Go↔Python:

- Go вызывает Python по HTTP (`POST /v1/predict/url`) и получает:
  - `score`
  - `risk`
  - `model_version`
  - `features`
- финальный вердикт вычисляется в Go с URL-first правилами.

## 3. ML-пайплайн (рабочая версия)

Используется 3-уровневая схема:

- Model A: URL classifier (`url_score`)
- Model B: text classifier (`text_score`)
- Model C: fusion classifier (`final_score`, `risk`)

Дополнительно применяются post-processing guards для снижения false positive на trusted/clean ссылках.

## 4. Реализованный backend-функционал

- Управление IMAP-аккаунтами:
  - create/list/update/delete
  - pause/resume
  - reset `last_uid`
- Опрос и сканирование:
  - периодический polling
  - `poll once` вручную
  - ручная проверка URL
- История и аналитика:
  - история по письмам
  - детали URL внутри письма
  - stats, timeseries
  - экспорт CSV/summary
- Пересчёт:
  - endpoint `POST /api/v1/rescore` для обновления старых verdict
- Диагностика:
  - `healthz`
  - `system/status`
  - журнал ошибок аккаунтов

## 5. Безопасность

- Пароли IMAP хранятся в зашифрованном виде (AES-GCM).
- Для шифрования используется `ACCOUNT_CREDENTIALS_KEY`.
- В `docker-compose` и `.env.example` чувствительные параметры вынесены в переменные окружения.
- Добавлена обратная совместимость со старыми plaintext-записями.

## 6. База данных и миграции

Текущее состояние:

- есть SQL-файлы в `backend/migrations`
- goose как инструмент сейчас не используется
- базовая схема БД создаётся автоматически при старте backend (`ensureBaseSchema`)

Это позволяет запускать проект на пустой БД без ручного применения миграций.

## 7. Основные API endpoints

- `GET /healthz`
- `GET /api/v1/system/status`
- `GET/POST/PATCH/DELETE /api/v1/accounts`
- `GET /api/v1/accounts/errors`
- `GET /api/v1/stats`
- `GET /api/v1/stats/timeseries`
- `GET /api/v1/history`
- `GET /api/v1/history/:emailID`
- `POST /api/v1/poll/once`
- `POST /api/v1/rescore`
- `POST /api/v1/check/url`
- `GET /api/v1/reports/detections.csv`
- `GET /api/v1/reports/summary`
- `GET /api/v1/reports/summary.csv`

## 8. Запуск

Из корня проекта:

```powershell
docker compose up --build
```

Адреса:

- UI: `http://localhost:8080/`
- backend health: `http://localhost:8080/healthz`
- ML info: `http://localhost:8000/v1/model`

## 9. Как временно остановить проект

Если нужно просто остановить контейнеры (без удаления):

```powershell
docker compose stop
```

Если нужно остановить и удалить контейнеры/сеть проекта:

```powershell
docker compose down
```

Если нужен полный сброс с удалением данных БД (volume):

```powershell
docker compose down -v
```

