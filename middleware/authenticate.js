/**
 * middleware/authenticate.js
 * Проверяет JWT-токен и прикрепляет данные пользователя к req.user.
 * Также проверяет, что сессия токена совпадает с активной сессией в хранилище
 * — это запрещает параллельные сессии.
 */

'use strict';

const jwt         = require('jsonwebtoken');
const { UserStore } = require('../models/userStore');
const { logger }  = require('../utils/logger');

/**
 * Middleware аутентификации.
 * Ожидает заголовок: Authorization: Bearer <token>
 */
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Токен не предоставлен' });
  }

  const token = authHeader.slice(7); // убираем "Bearer "

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    const reason = err.name === 'TokenExpiredError' ? 'Токен истёк' : 'Неверный токен';
    logger.auth('Неудачная попытка доступа', { reason, ip: req.ip });
    return res.status(401).json({ error: reason });
  }

  // Проверяем, что пользователь существует
  const user = UserStore.findById(payload.userId);
  if (!user) {
    return res.status(401).json({ error: 'Пользователь не найден' });
  }

  // ── Запрет параллельных сессий ────────────────────────────────────────────
  // Каждый токен содержит sessionId; если он не совпадает с activeSession —
  // значит, пользователь уже вошёл с другого места.
  if (user.activeSession !== payload.sessionId) {
    logger.auth('Обнаружена параллельная сессия', {
      userId    : user.id,
      username  : user.username,
      sessionId : payload.sessionId,
      active    : user.activeSession,
      ip        : req.ip,
    });
    return res.status(401).json({
      error: 'Сессия недействительна. Войдите снова.',
    });
  }

  req.user = {
    id       : user.id,
    username : user.username,
    email    : user.email,
    role     : user.role,
    sessionId: payload.sessionId,
  };

  next();
}

/**
 * Фабрика middleware для ролевого контроля доступа.
 * @param {...string} roles — допустимые роли
 * @returns {Function} middleware
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Не аутентифицирован' });
    }
    if (!roles.includes(req.user.role)) {
      logger.auth('Отказано в доступе (роль)', {
        userId  : req.user.id,
        role    : req.user.role,
        required: roles,
        path    : req.path,
      });
      return res.status(403).json({
        error: `Доступ запрещён. Требуется роль: ${roles.join(' | ')}`,
      });
    }
    next();
  };
}

module.exports = { authenticate, requireRole };
