/**
 * tests/manual-test.js
 * Скрипт ручного тестирования всех сценариев лабораторной работы.
 * Запуск: node tests/manual-test.js
 * (Сервер должен быть запущен на localhost:3000)
 */

'use strict';

const BASE = 'http://localhost:3000/api';

/** Цветной вывод */
const c = {
  green : s => `\x1b[32m${s}\x1b[0m`,
  red   : s => `\x1b[31m${s}\x1b[0m`,
  yellow: s => `\x1b[33m${s}\x1b[0m`,
  cyan  : s => `\x1b[36m${s}\x1b[0m`,
  bold  : s => `\x1b[1m${s}\x1b[0m`,
};

let passed = 0;
let failed = 0;

async function request(method, path, body, token) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (token) opts.headers['Authorization'] = `Bearer ${token}`;
  if (body)  opts.body = JSON.stringify(body);

  const res  = await fetch(`${BASE}${path}`, opts);
  const data = await res.json();
  return { status: res.status, data };
}

function assert(name, condition, details = '') {
  if (condition) {
    console.log(c.green(`  ✓ ${name}`));
    passed++;
  } else {
    console.log(c.red(`  ✗ ${name}`) + (details ? ` — ${details}` : ''));
    failed++;
  }
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ─────────────────────────────────────────────────────────────────────────────
async function runTests() {
  console.log(c.bold('\n🛡️  AuthShield — Тестирование\n'));

  // ── 1. Регистрация ──────────────────────────────────────────────────────────
  console.log(c.cyan('[ 1. Регистрация ]'));

  const reg1 = await request('POST', '/auth/register', {
    username: 'alice', email: 'alice@test.com', password: 'SecurePass1!'
  });
  assert('Успешная регистрация (201)', reg1.status === 201);
  assert('Пароль не возвращается', !reg1.data.user?.passwordHash);

  const reg2 = await request('POST', '/auth/register', {
    username: 'alice', email: 'alice2@test.com', password: 'SecurePass1!'
  });
  assert('Дубликат username → 409', reg2.status === 409);

  const reg3 = await request('POST', '/auth/register', {
    username: 'bo', email: 'bo@test.com', password: 'short'
  });
  assert('Короткий username → 400', reg3.status === 400);

  // Регистрируем второго пользователя и администратора
  await request('POST', '/auth/register', {
    username: 'bob', email: 'bob@test.com', password: 'SecurePass2!'
  });

  // Для теста — разрешаем передать роль (нужен ALLOW_ROLE_PARAM=true в .env)
  const regAdmin = await request('POST', '/auth/register', {
    username: 'admin', email: 'admin@test.com', password: 'AdminPass!999', role: 'admin'
  });
  assert('Регистрация admin (или user если ALLOW_ROLE_PARAM=false)', regAdmin.status === 201);

  // ── 2. Вход ─────────────────────────────────────────────────────────────────
  console.log(c.cyan('\n[ 2. Вход ]'));

  const login1 = await request('POST', '/auth/login', {
    username: 'alice', password: 'SecurePass1!'
  });
  assert('Успешный вход (200)', login1.status === 200);
  assert('Возвращает accessToken', !!login1.data.accessToken);
  assert('Возвращает refreshToken', !!login1.data.refreshToken);
  assert('expiresIn = 900', login1.data.expiresIn === 900);

  const aliceToken = login1.data.accessToken;
  const aliceRefresh = login1.data.refreshToken;

  const login2 = await request('POST', '/auth/login', {
    username: 'alice', password: 'WrongPassword'
  });
  assert('Неверный пароль → 401', login2.status === 401);

  // ── 3. Rate limiting ────────────────────────────────────────────────────────
  console.log(c.cyan('\n[ 3. Rate Limiting (3 попытки/мин) ]'));

  // Уже сделали 1 неудачную попытку выше, добавляем ещё 2
  await request('POST', '/auth/login', { username: 'alice', password: 'wrong' });
  await request('POST', '/auth/login', { username: 'alice', password: 'wrong' });
  const blocked = await request('POST', '/auth/login', { username: 'alice', password: 'wrong' });
  assert('Блокировка после 3 неудач → 429', blocked.status === 429);

  // ── 4. Защищённые маршруты ──────────────────────────────────────────────────
  console.log(c.cyan('\n[ 4. Защищённые маршруты ]'));

  const profile = await request('GET', '/protected/profile', null, aliceToken);
  assert('Профиль доступен с токеном (200)', profile.status === 200);

  const noToken = await request('GET', '/protected/profile', null, null);
  assert('Профиль без токена → 401', noToken.status === 401);

  const modAccess = await request('GET', '/protected/moderator', null, aliceToken);
  assert('Обычный user → moderator 403', modAccess.status === 403);

  const adminAccess = await request('GET', '/protected/admin', null, aliceToken);
  assert('Обычный user → admin 403', adminAccess.status === 403);

  // ── 5. Параллельные сессии ──────────────────────────────────────────────────
  console.log(c.cyan('\n[ 5. Запрет параллельных сессий ]'));

  // alice логинится второй раз — первый токен должен стать недействительным
  await sleep(500);
  const login3 = await request('POST', '/auth/login', {
    username: 'alice', password: 'SecurePass1!'
  });
  // Немного подождём после rate-limit окна (в тесте можем получить 429)
  if (login3.status === 200) {
    const newToken = login3.data.accessToken;
    const oldProfile = await request('GET', '/protected/profile', null, aliceToken);
    assert('Старый токен после нового входа → 401', oldProfile.status === 401);
    const newProfile = await request('GET', '/protected/profile', null, newToken);
    assert('Новый токен работает', newProfile.status === 200);
  } else {
    console.log(c.yellow('  ⚠ Пропуск (rate limit ещё активен)'));
  }

  // ── 6. Refresh токен ────────────────────────────────────────────────────────
  console.log(c.cyan('\n[ 6. Обновление токена ]'));

  const refresh = await request('POST', '/auth/refresh', { refreshToken: aliceRefresh });
  // Может быть 401, если сессия изменилась выше — это корректное поведение
  assert(
    'Refresh возвращает новый accessToken или 401 (сессия изменилась)',
    refresh.status === 200 || refresh.status === 401
  );

  // ── 7. Восстановление пароля ────────────────────────────────────────────────
  console.log(c.cyan('\n[ 7. Восстановление пароля (одноразовый токен) ]'));

  const forgot = await request('POST', '/auth/forgot-password', { email: 'bob@test.com' });
  assert('Запрос сброса пароля (200)', forgot.status === 200);
  assert('Одинаковый ответ для существующего email', forgot.data.message.includes('зарегистрирован'));

  const forgotFake = await request('POST', '/auth/forgot-password', { email: 'notexist@test.com' });
  assert('Одинаковый ответ для несуществующего email', forgotFake.status === 200);
  assert('Тексты совпадают (защита от перебора)', forgot.data.message === forgotFake.data.message);

  if (forgot.data._devOnly?.resetToken) {
    const resetToken = forgot.data._devOnly.resetToken;

    const resetBad = await request('POST', '/auth/reset-password', {
      token: resetToken, newPassword: 'short'
    });
    assert('Слабый новый пароль → 400', resetBad.status === 400);

    const resetOk = await request('POST', '/auth/reset-password', {
      token: resetToken, newPassword: 'NewSecurePass!123'
    });
    assert('Успешный сброс пароля (200)', resetOk.status === 200);

    const resetReuse = await request('POST', '/auth/reset-password', {
      token: resetToken, newPassword: 'AnotherPass!456'
    });
    assert('Повторное использование токена → 400', resetReuse.status === 400);

    const loginNew = await request('POST', '/auth/login', {
      username: 'bob', password: 'NewSecurePass!123'
    });
    assert('Вход с новым паролем работает', loginNew.status === 200);
  }

  // ── 8. Выход ────────────────────────────────────────────────────────────────
  console.log(c.cyan('\n[ 8. Выход ]'));

  const loginForLogout = await request('POST', '/auth/login', {
    username: 'alice', password: 'SecurePass1!'
  });
  if (loginForLogout.status === 200) {
    const t = loginForLogout.data.accessToken;
    const logout = await request('POST', '/auth/logout', null, t);
    assert('Выход успешен (200)', logout.status === 200);

    const afterLogout = await request('GET', '/protected/profile', null, t);
    assert('Токен после выхода недействителен → 401', afterLogout.status === 401);
  }

  // ── Итог ───────────────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(50));
  console.log(c.bold(`Результат: ${c.green(passed + ' пройдено')} / ${c.red(failed + ' провалено')}`));
  console.log('─'.repeat(50) + '\n');
}

runTests().catch(err => {
  console.error(c.red('Ошибка тестирования:'), err.message);
  console.error('Убедитесь, что сервер запущен: npm start');
});
