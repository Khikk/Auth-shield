/**
 * middleware/rateLimiter.js
 * Ограничение попыток входа: максимум 3 попытки в минуту с одного IP.
 */

'use strict';

const rateLimit = require('express-rate-limit');
const { logger } = require('../utils/logger');

/** Лимит для /login */
const loginLimiter = rateLimit({
  windowMs         : 60 * 1000,   // 1 минута
  max              : 3,            // 3 попытки
  standardHeaders  : true,
  legacyHeaders    : false,
  skipSuccessfulRequests: true,    // считаем только неудачные

  handler(req, res) {
    logger.auth('Превышен лимит попыток входа', {
      ip      : req.ip,
      username: req.body?.username || 'unknown',
    });
    res.status(429).json({
      error     : 'Слишком много попыток входа. Попробуйте через 1 минуту.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000),
    });
  },
});

/** Лимит для /register — защита от спама */
const registerLimiter = rateLimit({
  windowMs       : 10 * 60 * 1000, // 10 минут
  max            : 5,
  standardHeaders: true,
  legacyHeaders  : false,
  message        : { error: 'Слишком много регистраций. Попробуйте позже.' },
});

/** Лимит для /forgot-password — защита от перебора email */
const forgotPasswordLimiter = rateLimit({
  windowMs       : 15 * 60 * 1000, // 15 минут
  max            : 3,
  standardHeaders: true,
  legacyHeaders  : false,
  message        : { error: 'Слишком много запросов сброса пароля. Попробуйте позже.' },
});

module.exports = { loginLimiter, registerLimiter, forgotPasswordLimiter };
