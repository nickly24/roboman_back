# Декомпозиция эпика цифровых сертификатов

Функциональные требования: `teacher-certificates-task.md`. Этот документ описывает инженерные задачи отдельно от бизнес-постановки.

| Задача | Результат | Зависимости | Проверка |
|---|---|---|---|
| 1. Модель и миграция | Отдельная таблица сертификатов, связь с teacher, уникальные номер/token/teacher, фото, состояния, даты, revision | ТЗ | Новая миграция на изолированной MySQL 8; FK, уникальность, отсутствие изменений прежних таблиц |
| 2. Закрытый API | OWNER CRUD/фото/publish/revoke; TEACHER собственный сертификат; optimistic concurrency | 1 | HTTP-тесты ролей, дубликатов, заполнения, stale revision |
| 3. Публичный API | Строгая проекция профиля, фото и QR без auth; draft 404, revoked/fired 410 | 1–2 | Нет служебных/финансовых полей; запросы без/с неверным bearer; немедленное закрытие фото при отзыве |
| 4. PDF и массовый экспорт | Серверный PDF с кириллическим шрифтом, фото, QR и пагинацией; ZIP максимум 100 | 2–3 | Открытие/извлечение текста/рендер всех страниц, декодирование QR, проверка содержимого ZIP |
| 5. Публичная страница | `/certificates/:token`, без ProtectedRoute/Layout, отдельный HTTP-клиент | 3 | Прямой URL без auth; просроченная сессия; 404/410; desktop/mobile |
| 6. Личный раздел | `/my-certificate`, navigation TEACHER, preview/link/PDF/пустые состояния | 2,4–5 | Только собственный профиль, нет административных действий |
| 7. Раздел администратора | `/teacher-certificates`, search/status/select/edit/photo/publish/revoke/PDF/ZIP | 2,4–5 | Жизненный цикл через интерфейс, errors, stale edits, invalid selection |
| 8. Интеграция и регрессия | Backend unittest, frontend Jest, production build, реальный local MySQL и browser QA | 1–7 | Отчёт с командами, результатами, ограничениями и артефактами |
| 9. Передача пользователю | Отчёт, локальный preview, deploy runbook, неприменённая миграция | 8 | Prod не тронут; нет commit/push; deployment требует отдельной отмашки |

## Согласованный контракт

- Owner: `GET/POST /api/teacher-certificates`, `GET/PUT /api/teacher-certificates/:id`, `POST /:id/publish`, `POST /:id/revoke`, `PUT/DELETE /:id/photo`, `GET /:id/pdf`, `POST /api/teacher-certificates/export` с `certificate_ids`.
- Teacher: `GET /api/teacher-certificates/me`, `GET /api/teacher-certificates/me/pdf`.
- Public: `GET /api/public/teacher-certificates/:token`, `GET /:token/photo`, `GET /:token/qr`.
- Состояния `draft`, `published`, `revoked`; публичный revoked/fired возвращает HTTP 410 с номером и состоянием без персональных полей.
- Авторизованный документ: `id`, `teacher_id`, `teacher_name`, `number`, `status`, `university`, `study_program`, `description`, `has_photo`, `photo_url`, `qr_url`, `public_url`, `public_path`, `issued_at`, `revision`, `branches` с `name` и `address`.
- Сады и имя вычисляются из текущих teachers/branch_teachers/branches. Публичная проекция не включает внутренние идентификаторы, revision, авторов и технические даты.
- Публичный клиент frontend не использует bearer и auth redirect interceptor.
- Изменяющие запросы существующего документа передают `revision`; фото — multipart `photo` + `revision`. После мутации возвращается обновлённый документ.
- `PUBLIC_CERTIFICATE_BASE_URL` задаёт канонический origin frontend (протокол, домен и при необходимости порт, без префикса пути) для ссылок и QR. Приложение размещается в корне этого адреса. Заголовки Host/Origin посетителя не определяют адрес сертификата. Без корректной настройки публикация и выгрузка возвращают ошибку конфигурации.

## Безопасные локальные проверки

Изолированная MySQL с новым каталогом данных и отдельным socket, синтетические записи, все DB-переменные явно локальные. Предыдущие приватные резервные копии prod не использовать. Не запускать deployment runner с дефолтами: в существующем проекте они ведут на удалённую базу. Frontend запускать с явным локальным `REACT_APP_API_BASE_URL`, поскольку его дефолтный адрес ведёт на prod.

## Порядок будущей публикации

Только после команды пользователя: подтвердить целевую базу и frontend URL; создать и проверить резервную копию; применить миграцию до запуска нового кода; отдельно создать коммиты в двух репозиториях и push main. При выпуске кода установить новые backend dependencies, настроить канонический URL и выполнить smoke проверки. Команда и checksum зафиксированы в `teacher-certificates-deployment.md`, результаты локальной проверки — в `teacher-certificates-implementation.md`.
