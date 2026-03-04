/**
 * utils/logger.js
 * Простой структурированный логгер с записью в файл и консоль.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const LOG_DIR  = path.join(__dirname, '..', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'auth.log');

// Создаём директорию, если не существует
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

/**
 * Форматирует и записывает строку лога.
 * @param {'INFO'|'WARN'|'ERROR'|'AUTH'} level
 * @param {string} message
 * @param {object} [meta]
 */
function write(level, message, meta = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta,
  };
  const line = JSON.stringify(entry) + '\n';

  // Консоль
  const prefix = {
    INFO  : '\x1b[36m[INFO]\x1b[0m',
    WARN  : '\x1b[33m[WARN]\x1b[0m',
    ERROR : '\x1b[31m[ERROR]\x1b[0m',
    AUTH  : '\x1b[35m[AUTH]\x1b[0m',
  }[level] || `[${level}]`;

  console.log(`${prefix} ${entry.timestamp} — ${message}`, Object.keys(meta).length ? meta : '');

  // Файл
  fs.appendFile(LOG_FILE, line, err => {
    if (err) console.error('Logger write error:', err);
  });
}

const logger = {
  info  : (msg, meta) => write('INFO',  msg, meta),
  warn  : (msg, meta) => write('WARN',  msg, meta),
  error : (msg, meta) => write('ERROR', msg, meta),
  /** Специальный уровень — все события аутентификации */
  auth  : (msg, meta) => write('AUTH',  msg, meta),
};

module.exports = { logger };
