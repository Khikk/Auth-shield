/**
 * models/userStore.js
 * Хранилище пользователей в памяти (заменяется на БД в продакшне).
 * Роли: 'user' | 'moderator' | 'admin'
 */

'use strict';

/** @type {Map<number, UserRecord>} */
const users = new Map();

/** @type {number} Счётчик auto-increment */
let nextId = 1;

/**
 * @typedef {Object} UserRecord
 * @property {number}  id
 * @property {string}  username
 * @property {string}  email
 * @property {string}  passwordHash
 * @property {'user'|'moderator'|'admin'} role
 * @property {Date}    createdAt
 * @property {Date|null} lastLogin
 * @property {string|null} activeSession   — ID текущей активной сессии
 * @property {string|null} resetToken      — одноразовый токен сброса пароля
 * @property {Date|null}   resetTokenExpires
 */

const UserStore = {
  /**
   * Создать нового пользователя.
   * @param {{ username:string, email:string, passwordHash:string, role?:string }} data
   * @returns {UserRecord}
   */
  create(data) {
    const user = {
      id               : nextId++,
      username         : data.username.trim(),
      email            : data.email.trim().toLowerCase(),
      passwordHash     : data.passwordHash,
      role             : data.role || 'user',
      createdAt        : new Date(),
      lastLogin        : null,
      activeSession    : null,
      resetToken       : null,
      resetTokenExpires: null,
    };
    users.set(user.id, user);
    return user;
  },

  /** @returns {UserRecord|undefined} */
  findById(id) {
    return users.get(Number(id));
  },

  /** @returns {UserRecord|undefined} */
  findByUsername(username) {
    for (const u of users.values()) {
      if (u.username.toLowerCase() === username.trim().toLowerCase()) return u;
    }
  },

  /** @returns {UserRecord|undefined} */
  findByEmail(email) {
    for (const u of users.values()) {
      if (u.email === email.trim().toLowerCase()) return u;
    }
  },

  /** @returns {UserRecord|undefined} */
  findByResetToken(token) {
    for (const u of users.values()) {
      if (u.resetToken === token) return u;
    }
  },

  /**
   * Обновить поля пользователя.
   * @param {number} id
   * @param {Partial<UserRecord>} fields
   * @returns {UserRecord|null}
   */
  update(id, fields) {
    const user = users.get(Number(id));
    if (!user) return null;
    Object.assign(user, fields);
    return user;
  },

  /**
   * Безопасное публичное представление (без хеша).
   * @param {UserRecord} user
   */
  sanitize(user) {
    const { passwordHash, resetToken, resetTokenExpires, activeSession, ...safe } = user;
    return {
      ...safe,
      // Экранирование строковых полей от XSS
      username : escapeHtml(safe.username),
      email    : escapeHtml(safe.email),
    };
  },

  /** @returns {UserRecord[]} */
  all() {
    return [...users.values()];
  },
};

/** Простое экранирование HTML-спецсимволов */
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;');
}

module.exports = { UserStore };
