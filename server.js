/**
 * AuthShield — Защищённый микросервис аутентификации
 * Лабораторная работа №1: Безопасная аутентификация
 */

require('dotenv').config();
const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const authRoutes   = require('./routes/auth');
const protectedRoutes = require('./routes/protected');
const { logger }   = require('./utils/logger');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Базовые middlewares ──────────────────────────────────────────────────────
app.use(helmet());          // Безопасные HTTP-заголовки
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── Логирование каждого запроса ──────────────────────────────────────────────
app.use((req, _res, next) => {
  logger.info(`${req.method} ${req.path} — IP: ${req.ip}`);
  next();
});

// ── Маршруты ─────────────────────────────────────────────────────────────────
app.use('/api/auth',      authRoutes);
app.use('/api/protected', protectedRoutes);

// Корень — статус сервиса
app.get('/', (_req, res) => {
  res.json({
    service : 'AuthShield',
    version : '1.0.0',
    status  : 'running',
    endpoints: {
      register        : 'POST /api/auth/register',
      login           : 'POST /api/auth/login',
      logout          : 'POST /api/auth/logout',
      refresh         : 'POST /api/auth/refresh',
      forgotPassword  : 'POST /api/auth/forgot-password',
      resetPassword   : 'POST /api/auth/reset-password',
      profile         : 'GET  /api/protected/profile',
      moderatorPanel  : 'GET  /api/protected/moderator',
      adminPanel      : 'GET  /api/protected/admin',
    },
  });
});

// ── Глобальный обработчик ошибок ─────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  logger.error(`Unhandled error: ${err.message}`);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  logger.info(`AuthShield запущен на порту ${PORT}`);
  console.log(`\n🛡️  AuthShield запущен → http://localhost:${PORT}\n`);
});

module.exports = app;
