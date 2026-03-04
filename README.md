# 🛡️ AuthShield — Защищённый микросервис аутентификации

> **Лабораторная работа №1** — Безопасная аутентификация  
> Реализация современных механизмов защиты: bcrypt, JWT, rate limiting, RBAC, одноразовые токены.

---

## Архитектура

```
authshield/
├── server.js                  # Точка входа, Express-приложение
├── .env.example               # Шаблон переменных окружения
├── package.json
│
├── models/
│   └── userStore.js           # Хранилище пользователей (in-memory)
│
├── middleware/
│   ├── authenticate.js        # JWT-проверка + запрет параллельных сессий
│   └── rateLimiter.js         # Rate limiting для входа/регистрации
│
├── routes/
│   ├── auth.js                # /register, /login, /logout, /refresh, /reset
│   └── protected.js           # /profile, /moderator, /admin
│
├── utils/
│   └── logger.js              # Структурированное логирование (файл + консоль)
│
├── logs/
│   └── auth.log               # Лог событий аутентификации (создаётся автоматически)
│
└── tests/
    └── manual-test.js         # Скрипт тестирования всех сценариев
```

---

## Быстрый старт

```bash
# 1. Установить зависимости
npm install

# 2. Создать файл окружения
cp .env.example .env

# 3. Сгенерировать секреты JWT
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Скопируйте вывод в JWT_SECRET, затем запустите снова для JWT_REFRESH_SECRET

# 4. Запустить сервер
npm start          # продакшн-режим
npm run dev        # режим разработки с hot-reload (nodemon)

# 5. Запустить тесты (в отдельном терминале)
npm test
```

---

## API-документация

### Аутентификация

#### `POST /api/auth/register`
Регистрация нового пользователя.

**Тело запроса:**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "SecurePass1!"
}
```

**Успешный ответ (201):**
```json
{
  "message": "Регистрация успешна",
  "user": { "id": 1, "username": "alice", "role": "user", ... }
}
```

---

#### `POST /api/auth/login`
Вход в систему. **Лимит: 3 попытки/минуту** с одного IP.

**Тело запроса:**
```json
{
  "username": "alice",
  "password": "SecurePass1!"
}
```

**Успешный ответ (200):**
```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresIn": 900
}
```

**Ошибки:**
- `401` — Неверные учётные данные
- `429` — Превышен лимит попыток

---

#### `POST /api/auth/logout`
Выход из системы. Инвалидирует текущую сессию.

**Заголовок:** `Authorization: Bearer <accessToken>`

---

#### `POST /api/auth/refresh`
Обновление access-токена по refresh-токену.

**Тело запроса:**
```json
{ "refreshToken": "eyJ..." }
```

**Ответ (200):**
```json
{ "accessToken": "eyJ...", "refreshToken": "eyJ...", "expiresIn": 900 }
```

---

#### `POST /api/auth/forgot-password`
Запрос сброса пароля. **Лимит: 3 запроса / 15 минут**.

```json
{ "email": "alice@example.com" }
```

В продакшне токен отправляется на email. В режиме разработки токен возвращается в `_devOnly.resetToken`.

---

#### `POST /api/auth/reset-password`
Сброс пароля одноразовым токеном (действует 30 минут).

```json
{
  "token": "abc123...",
  "newPassword": "NewSecurePass!123"
}
```

---

### Защищённые маршруты

Все требуют заголовка: `Authorization: Bearer <accessToken>`

| Маршрут | Метод | Доступ |
|---------|-------|--------|
| `/api/protected/profile` | GET | user, moderator, admin |
| `/api/protected/moderator` | GET | moderator, admin |
| `/api/protected/admin` | GET | admin |
| `/api/protected/users` | GET | admin |

---

## Реализованные механизмы безопасности

### 1. Хеширование паролей
- Алгоритм: **bcrypt** с cost factor **12**
- Пароль никогда не хранится в открытом виде
- Защита от тайминг-атак при проверке несуществующего пользователя

### 2. JWT-токены
- **Access token**: срок жизни **15 минут**
- **Refresh token**: срок жизни **7 дней**, ротируется при обновлении
- Каждый токен содержит `sessionId` для контроля параллельных сессий

### 3. Rate Limiting
| Маршрут | Лимит | Окно |
|---------|-------|------|
| `/login` | 3 попытки | 1 минута |
| `/register` | 5 попыток | 10 минут |
| `/forgot-password` | 3 попытки | 15 минут |

### 4. Ролевая модель (RBAC)
```
user  →  profile
moderator → profile, moderator
admin → profile, moderator, admin, users
```

### 5. Запрет параллельных сессий
При каждом входе генерируется новый `sessionId`. Предыдущие токены автоматически становятся недействительными.

### 6. Экранирование данных
Все строковые поля пользователя экранируются от XSS перед возвратом клиенту.

### 7. Логирование
Все события AUTH записываются в `logs/auth.log` в JSON-формате с timestamp и IP.

### 8. Безопасные HTTP-заголовки
Helmet добавляет заголовки: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` и др.

---

## Переменные окружения

| Переменная | Описание |
|-----------|----------|
| `PORT` | Порт сервера (по умолчанию 3000) |
| `JWT_SECRET` | Секрет для access-токенов (мин. 64 символа) |
| `JWT_REFRESH_SECRET` | Секрет для refresh-токенов (мин. 64 символа) |
| `ALLOW_ROLE_PARAM` | `true` — разрешить передачу роли при регистрации |
| `NODE_ENV` | `development` / `production` |

---

## Пример тестирования через curl

```bash
# Регистрация
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@test.com","password":"SecurePass1!"}'

# Вход
TOKEN=$(curl -sX POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SecurePass1!"}' | jq -r '.accessToken')

# Доступ к профилю
curl http://localhost:3000/api/protected/profile \
  -H "Authorization: Bearer $TOKEN"

# Попытка доступа к admin (получим 403)
curl http://localhost:3000/api/protected/admin \
  -H "Authorization: Bearer $TOKEN"
```
