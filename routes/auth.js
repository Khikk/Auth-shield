/**
 * routes/auth.js
 * Маршруты аутентификации:
 *   POST /api/auth/register
 *   POST /api/auth/login
 *   POST /api/auth/logout
 *   POST /api/auth/refresh
 *   POST /api/auth/forgot-password
 *   POST /api/auth/reset-password
 */

'use strict';

const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');
const { UserStore }  = require('../models/userStore');
const { logger }     = require('../utils/logger');
const { authenticate }                                    = require('../middleware/authenticate');
const { loginLimiter, registerLimiter, forgotPasswordLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────────
// Вспомогательные функции
// ─────────────────────────────────────────────────────────────────────────────

/** Создаёт пару access + refresh токенов для пользователя. */
function generateTokens(user, sessionId) {
  const accessToken = jwt.sign(
    { userId: user.id, role: user.role, sessionId },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId: user.id, sessionId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
}

/** Простая валидация: не пустое, минимальная длина. */
function validate(value, minLen = 1) {
  return typeof value === 'string' && value.trim().length >= minLen;
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/register
// ─────────────────────────────────────────────────────────────────────────────
router.post('/register', registerLimiter, async (req, res) => {
  const { username, email, password, role } = req.body;

  // Валидация входных данных
  if (!validate(username, 3))
    return res.status(400).json({ error: 'Имя пользователя — минимум 3 символа' });
  if (!validate(email, 5) || !email.includes('@'))
    return res.status(400).json({ error: 'Неверный формат email' });
  if (!validate(password, 8))
    return res.status(400).json({ error: 'Пароль — минимум 8 символов' });

  // Проверка уникальности
  if (UserStore.findByUsername(username))
    return res.status(409).json({ error: 'Пользователь с таким именем уже существует' });
  if (UserStore.findByEmail(email))
    return res.status(409).json({ error: 'Email уже зарегистрирован' });

  // Роль: только 'user' по умолчанию; admin-роль — только через ENV-флаг
  const allowedRoles  = ['user', 'moderator', 'admin'];
  const assignedRole  = allowedRoles.includes(role) && process.env.ALLOW_ROLE_PARAM === 'true'
    ? role
    : 'user';

  // Хеширование пароля с bcrypt (cost factor 12 — баланс безопасности и скорости)
  const passwordHash = await bcrypt.hash(password, 12);

  const user = UserStore.create({ username, email, passwordHash, role: assignedRole });

  logger.auth('Регистрация нового пользователя', {
    userId  : user.id,
    username: user.username,
    role    : user.role,
    ip      : req.ip,
  });

  res.status(201).json({
    message: 'Регистрация успешна',
    user   : UserStore.sanitize(user),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/login
// ─────────────────────────────────────────────────────────────────────────────
router.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!validate(username) || !validate(password)) {
    return res.status(400).json({ error: 'Введите имя пользователя и пароль' });
  }

  const user = UserStore.findByUsername(username);

  // Намеренно одинаковое время ответа при несуществующем пользователе (защита от тайминг-атак)
  const dummyHash = '$2a$12$invalidhashfortimingnormalization.....';
  const isValid = user
    ? await bcrypt.compare(password, user.passwordHash)
    : await bcrypt.compare(password, dummyHash).then(() => false);

  if (!isValid) {
    logger.auth('Неудачная попытка входа', {
      username: username,
      exists  : !!user,
      ip      : req.ip,
    });
    return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
  }

  // Генерация уникального ID сессии (UUID v4)
  const sessionId = crypto.randomUUID();

  // Генерация токенов
  const { accessToken, refreshToken } = generateTokens(user, sessionId);

  // Сохраняем активную сессию (запрет параллельных сессий)
  UserStore.update(user.id, {
    activeSession: sessionId,
    lastLogin    : new Date(),
  });

  logger.auth('Успешный вход', {
    userId  : user.id,
    username: user.username,
    role    : user.role,
    ip      : req.ip,
  });

  res.json({
    message     : 'Вход выполнен',
    accessToken,
    refreshToken,
    expiresIn   : 900, // 15 минут в секундах
    user        : UserStore.sanitize(user),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/logout
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', authenticate, (req, res) => {
  // Сбрасываем активную сессию — токен станет недействительным
  UserStore.update(req.user.id, { activeSession: null });

  logger.auth('Выход из системы', {
    userId  : req.user.id,
    username: req.user.username,
    ip      : req.ip,
  });

  res.json({ message: 'Выход выполнен' });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/refresh
// Обновление access-токена по refresh-токену
// ─────────────────────────────────────────────────────────────────────────────
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh-токен не предоставлен' });
  }

  let payload;
  try {
    payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  } catch {
    return res.status(401).json({ error: 'Недействительный или истёкший refresh-токен' });
  }

  if (payload.type !== 'refresh') {
    return res.status(401).json({ error: 'Неверный тип токена' });
  }

  const user = UserStore.findById(payload.userId);
  if (!user || user.activeSession !== payload.sessionId) {
    return res.status(401).json({ error: 'Сессия недействительна' });
  }

  // Ротация сессии при обновлении (опционально — повышает безопасность)
  const newSessionId = crypto.randomUUID();
  UserStore.update(user.id, { activeSession: newSessionId });

  const { accessToken, refreshToken: newRefreshToken } = generateTokens(user, newSessionId);

  logger.auth('Обновление токена', { userId: user.id, ip: req.ip });

  res.json({
    accessToken,
    refreshToken: newRefreshToken,
    expiresIn   : 900,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/forgot-password
// Генерирует одноразовый токен сброса пароля (без SMS)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/forgot-password', forgotPasswordLimiter, (req, res) => {
  const { email } = req.body;

  if (!validate(email, 5)) {
    return res.status(400).json({ error: 'Введите email' });
  }

  const user = UserStore.findByEmail(email);

  // Одинаковый ответ независимо от наличия email (защита от перебора)
  if (user) {
    const resetToken   = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 30 * 60 * 1000); // 30 минут

    UserStore.update(user.id, {
      resetToken        : resetToken,
      resetTokenExpires : resetExpires,
    });

    // В реальном приложении здесь — отправка email.
    // В учебных целях токен возвращается в ответе.
    logger.auth('Запрос сброса пароля', {
      userId : user.id,
      email  : user.email,
      ip     : req.ip,
    });

    // ⚠️ ТОЛЬКО ДЛЯ РАЗРАБОТКИ — в продакшне убрать resetToken из ответа!
    return res.json({
      message   : 'Если email зарегистрирован, инструкции отправлены.',
      _devOnly  : { resetToken },
    });
  }

  res.json({ message: 'Если email зарегистрирован, инструкции отправлены.' });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/reset-password
// Сброс пароля по одноразовому токену
// ─────────────────────────────────────────────────────────────────────────────
router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!validate(token, 10) || !validate(newPassword, 8)) {
    return res.status(400).json({ error: 'Токен и новый пароль (мин. 8 символов) обязательны' });
  }

  const user = UserStore.findByResetToken(token);

  if (!user || !user.resetTokenExpires || user.resetTokenExpires < new Date()) {
    return res.status(400).json({ error: 'Токен недействителен или истёк' });
  }

  const passwordHash = await bcrypt.hash(newPassword, 12);

  // Сохраняем новый пароль и инвалидируем все сессии и токен сброса
  UserStore.update(user.id, {
    passwordHash      : passwordHash,
    resetToken        : null,
    resetTokenExpires : null,
    activeSession     : null,  // разлогиниваем все устройства
  });

  logger.auth('Пароль успешно сброшен', {
    userId  : user.id,
    username: user.username,
    ip      : req.ip,
  });

  res.json({ message: 'Пароль успешно изменён. Войдите с новым паролем.' });
});

module.exports = router;
