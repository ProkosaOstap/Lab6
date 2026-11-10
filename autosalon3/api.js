// RESTful API для доступу до даних системи та керування ними.
//
// Ендпоінти (таблиці: brands, trims, clients, options, sales):
//   GET    /api                 — список ендпоінтів
//   GET    /api/:table          — список записів          (доступно всім)
//   GET    /api/:table/:id      — один запис              (доступно всім)
//   POST   /api/:table          — створення            (manager / admin)
//   PUT    /api/:table/:id      — оновлення            (manager / admin)
//   DELETE /api/:table/:id      — видалення            (manager / admin)
//
// Формати відповідей: JSON. Коди: 200 OK, 201 Created, 400 помилки
// валідації { errors: { поле: текст } }, 401 не авторизовано, 403 заборонено
// для ролі, 404 не знайдено.
//
// Авторизація: сесія браузера АБО заголовок Authorization: Basic
// (логін:пароль) — для API-клієнтів, напр. curl -u manager:manager123.

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('./db');
const entities = require('./entities');
const { validateEntity } = entities;
const { ROLE_NAMES } = require('./auth');

const router = express.Router();

// ---------- Авторизація API-запитів (сесія або Basic) ----------
function apiAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();

  // Basic authentication: Authorization: Basic base64(логін:пароль)
  const h = req.headers.authorization || '';
  if (h.startsWith('Basic ')) {
    try {
      const [username, password] = Buffer.from(h.slice(6), 'base64').toString('utf8').split(':');
      const user = db.all('users').find(u => u.username === String(username || '').trim());
      if (user && bcrypt.compareSync(String(password || ''), user.password_hash)) {
        req.user = { id: user.id, username: user.username, full_name: user.full_name, role: user.role };
        return next();
      }
      res.set('WWW-Authenticate', 'Basic realm="Autosalon API"');
      return res.status(401).json({ error: 'Невірний логін або пароль' });
    } catch {
      return res.status(400).json({ error: 'Некоректний заголовок Authorization' });
    }
  }
  res.set('WWW-Authenticate', 'Basic realm="Autosalon API"');
  return res.status(401).json({ error: 'Потрібна авторизація: сесія або Basic (логін:пароль)' });
}

// перевірка ролі для операцій зміни даних
function apiRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Дія заборонена для ролі «${ROLE_NAMES[req.user.role] || req.user.role}». Потрібна роль: ${roles.map(r => ROLE_NAMES[r]).join(' або ')}.`
      });
    }
    next();
  };
}

const WRITE = apiRole('manager', 'admin'); // змінювати дані можуть manager/admin

// ---------- GET /api — опис ендпоінтів ----------
router.get('/', (req, res) => {
  res.json({
    name: 'Автосалон RESTful API',
    tables: Object.values(entities).map(e => e.key),
    endpoints: {
      'GET /api/:table': 'список записів (доступно всім)',
      'GET /api/:table/:id': 'один запис (доступно всім)',
      'POST /api/:table': 'створення запису (manager/admin)',
      'PUT /api/:table/:id': 'оновлення запису (manager/admin)',
      'DELETE /api/:table/:id': 'видалення запису (manager/admin)'
    },
    auth: 'сесія браузера або заголовок Authorization: Basic логін:пароль'
  });
});

// ---------- Утиліти ----------
function findTable(req, res) {
  const entity = entities[req.params.table];
  if (!entity) {
    res.status(404).json({ error: `Невідома таблиця: ${req.params.table}` });
    return null;
  }
  return entity;
}

// JSON-подання запису (продажу — з вибраними опціями)
function rowToJson(entity, row) {
  const json = { ...row };
  if (entity.key === 'sales') {
    json.options = db.getSaleOptions(row.id);
    const client = db.get('clients', row.client_id);
    const trim = db.get('trims', row.trim_id);
    json.client_name = client ? client.full_name : null;
    json.trim_name = trim ? trim.name : null;
  }
  if (entity.key === 'trims') {
    const brand = db.get('brands', row.brand_id);
    json.brand_name = brand ? brand.name : null;
  }
  return json;
}

// приведення полів (зовнішні ключі — числа) і збереження
function saveRecord(entity, row, values, id = null) {
  const record = { ...values };
  if (entity.key === 'sales') {
    const optionIds = values.options;
    delete record.options;
    if (id === null) {
      const created = db.insert('sales', record);
      db.setSaleOptions(created.id, optionIds);
      return db.get('sales', created.id);
    }
    db.update('sales', id, record);
    db.setSaleOptions(id, optionIds);
    return db.get('sales', id);
  }
  for (const f of entity.fields) {
    if (['brand_id', 'client_id', 'trim_id'].includes(f.name)) record[f.name] = Number(record[f.name]);
  }
  if (id === null) return db.insert(entity.key, record);
  return db.update(entity.key, id, record);
}

// ---------- Маршрути ----------

// список
router.get('/:table', (req, res) => {
  const entity = findTable(req, res);
  if (!entity) return;
  res.json(db.all(entity.key).map(r => rowToJson(entity, r)));
});

// один запис
router.get('/:table/:id(\\d+)', (req, res) => {
  const entity = findTable(req, res);
  if (!entity) return;
  const row = db.get(entity.key, req.params.id);
  if (!row) return res.status(404).json({ error: 'Запис не знайдено' });
  res.json(rowToJson(entity, row));
});

// створення
router.post('/:table', apiAuth, WRITE, express.json(), (req, res) => {
  const entity = findTable(req, res);
  if (!entity) return;
  const { errors, values } = validateEntity(entity, req.body || {});
  if (Object.keys(errors).length > 0) {
    return res.status(400).json({ error: 'Помилки валідації', errors });
  }
  const created = saveRecord(entity, null, values);
  res.status(201).json(rowToJson(entity, created));
});

// оновлення
router.put('/:table/:id(\\d+)', apiAuth, WRITE, express.json(), (req, res) => {
  const entity = findTable(req, res);
  if (!entity) return;
  const row = db.get(entity.key, req.params.id);
  if (!row) return res.status(404).json({ error: 'Запис не знайдено' });

  const { errors, values } = validateEntity(entity, req.body || {}, row.id);
  if (Object.keys(errors).length > 0) {
    return res.status(400).json({ error: 'Помилки валідації', errors });
  }
  const updated = saveRecord(entity, row.id, values, row.id);
  res.json(rowToJson(entity, updated));
});

// видалення
router.delete('/:table/:id(\\d+)', apiAuth, WRITE, (req, res) => {
  const entity = findTable(req, res);
  if (!entity) return;
  const row = db.get(entity.key, req.params.id);
  if (!row) return res.status(404).json({ error: 'Запис не знайдено' });

  // посилальна цілісність
  if (entity.deleteBlockedBy) {
    const { table, fk, message } = entity.deleteBlockedBy;
    if (db.findBy(table, fk, row.id).length > 0) {
      return res.status(409).json({ error: message });
    }
  }
  if (entity.cascade === 'sale_options') db.removeSaleOptions(row.id);
  db.remove(entity.key, row.id);
  res.json({ ok: true, deleted: Number(req.params.id) });
});

module.exports = router;
