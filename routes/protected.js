/**
 * routes/protected.js
 * Защищённые маршруты с ролевой моделью доступа.
 *
 *   GET /api/protected/profile     — любой авторизованный
 *   GET /api/protected/moderator   — moderator | admin
 *   GET /api/protected/admin       — только admin
 *   GET /api/protected/users       — только admin (список пользователей)
 */

'use strict';

const express        = require('express');
const { authenticate, requireRole } = require('../middleware/authenticate');
const { UserStore }  = require('../models/userStore');
const { logger }     = require('../utils/logger');

const router = express.Router();

// Все маршруты требуют аутентификации
router.use(authenticate);

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/protected/profile — доступен любому аутентифицированному пользователю
// ─────────────────────────────────────────────────────────────────────────────
router.get('/profile', (req, res) => {
  const user = UserStore.findById(req.user.id);
  res.json({
    message: 'Профиль пользователя',
    user   : UserStore.sanitize(user),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/protected/moderator — moderator и admin
// ─────────────────────────────────────────────────────────────────────────────
router.get('/moderator', requireRole('moderator', 'admin'), (req, res) => {
  logger.info('Доступ к панели модератора', { userId: req.user.id });
  res.json({
    message    : 'Панель модератора',
    accessedBy : req.user.username,
    role       : req.user.role,
    capabilities: [
      'Просмотр жалоб пользователей',
      'Блокировка контента',
      'Временная блокировка пользователей',
    ],
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/protected/admin — только admin
// ─────────────────────────────────────────────────────────────────────────────
router.get('/admin', requireRole('admin'), (req, res) => {
  logger.auth('Доступ к панели администратора', {
    userId  : req.user.id,
    username: req.user.username,
    ip      : req.ip,
  });
  res.json({
    message    : 'Панель администратора',
    accessedBy : req.user.username,
    capabilities: [
      'Управление пользователями',
      'Изменение ролей',
      'Просмотр логов',
      'Системные настройки',
    ],
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/protected/users — список всех пользователей (admin only)
// ─────────────────────────────────────────────────────────────────────────────
router.get('/users', requireRole('admin'), (req, res) => {
  const users = UserStore.all().map(UserStore.sanitize);
  res.json({
    total: users.length,
    users,
  });
});

module.exports = router;
