/**
 * Онлайн — защищённый сервер (Cloudflare Worker)
 * -------------------------------------------------------------------------
 * Первый шаг нового проекта: список состава групп (номер группы + номер в
 * группе, без имён пока) и распределение заданий по теократии, которые
 * автоматически видны ответственным за свои группы, с подсветкой недавно
 * изменённых. Архитектура и уровень защиты — как у "Учёт Отчётов
 * Возвещателей": пароли хэшируются на сервере, вход по токену, роли
 * проверяются заново при каждом запросе (не только в интерфейсе).
 *
 * ПЕРЕД ДЕПЛОЕМ:
 * 1. Впишите ниже свой BIN_ID (создать — см. jsonbin.io, "Create Bin",
 *    вставить туда пустой объект {}).
 * 2. В Cloudflare Dashboard -> ваш Worker -> Settings -> Variables and
 *    Secrets добавьте ТРИ секрета (тип "Secret", не "Text"):
 *      JSONBIN_KEY        — Master Key от JSONBin.io
 *      SESSION_SECRET     — любая длинная случайная строка (40+ символов)
 *      SEED_ADMIN_EMAIL   — email для самого первого супер-админа
 *      SEED_ADMIN_PASSWORD— временный пароль для него (смените после входа)
 * 3. Впишите ALLOWED_ORIGIN — адрес вашего сайта на GitHub Pages.
 */

const BIN_ID = "6aa7b166ac6210605aca97cd";
const ALLOWED_ORIGIN = "https://nifork-oss.github.io"; // <-- проверьте домен
const TOKEN_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000; // 30 дней

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

/* ============== крипто-утилиты (пароли + токены) — как в tablitsa ============== */

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(len = 16) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return toHex(arr.buffer);
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return toHex(buf);
}

async function hashPassword(password) {
  const salt = randomHex();
  const hash = await sha256Hex(salt + password);
  return `s2$${salt}$${hash}`;
}

async function verifyPassword(password, stored) {
  if (!stored) return false;
  if (typeof stored === "string" && stored.startsWith("s2$")) {
    const [, salt, hash] = stored.split("$");
    const check = await sha256Hex(salt + password);
    return check === hash;
  }
  return stored === password;
}

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function hmacKey(env) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signToken(payload, env) {
  const key = await hmacKey(env);
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return `${body}.${b64url(sig)}`;
}

async function verifyToken(token, env) {
  try {
    const [body, sig] = token.split(".");
    if (!body || !sig) return null;
    const key = await hmacKey(env);
    const valid = await crypto.subtle.verify("HMAC", key, b64urlToBytes(sig), new TextEncoder().encode(body));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(body)));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

async function getAuthUser(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return null;
  return await verifyToken(token, env);
}

/* ============== доступ к JSONBin (с повторными попытками) ============== */

async function fetchJsonBinWithRetry(url, options, attempts = 4) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return res;
      let bodyText = "";
      try { bodyText = await res.text(); } catch (e2) { /* нет тела — ладно */ }
      lastErr = new Error(`JSONBin вернул ошибку (код ${res.status})${bodyText ? ": " + bodyText.slice(0, 300) : ""}`);
      // При превышении лимита запросов (429) JSONBin обычно "отпускает" не
      // сразу — обычной короткой паузы мало, ждём заметно дольше.
      if (res.status === 429) {
        if (i < attempts - 1) await new Promise((resolve) => setTimeout(resolve, 1500 * (i + 1)));
        continue;
      }
    } catch (e) {
      lastErr = e;
    }
    if (i < attempts - 1) {
      await new Promise((resolve) => setTimeout(resolve, 400 * (i + 1)));
    }
  }
  throw lastErr;
}

/* ============== сжатие (на случай, если база вырастет) ============== */

function bufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function gzipCompress(str) {
  const stream = new Blob([str]).stream().pipeThrough(new CompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return bufferToBase64(buffer);
}

async function gzipDecompress(base64) {
  const buffer = base64ToBuffer(base64);
  const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream("gzip"));
  const text = await new Response(stream).text();
  return JSON.parse(text);
}

async function readBoard(env) {
  const res = await fetchJsonBinWithRetry(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
    headers: { "X-Master-Key": env.JSONBIN_KEY },
  });
  const data = await res.json();
  const raw = data.record;
  let record;

  if (raw && typeof raw === "object" && typeof raw.gzip === "string") {
    record = await gzipDecompress(raw.gzip);
  } else {
    record = raw && typeof raw === "object" ? raw : {};
  }

  if (!Array.isArray(record.users)) record.users = [];
  // Состав групп: [{ id, group, position, status }] — без имён пока.
  if (!Array.isArray(record.groupRoster)) record.groupRoster = [];

  // Расписание встреч — 4 отдельные таблицы, каждая ключом по дате недели
  // (ISO-строка "YYYY-MM-DD", среда для будней/учебных, воскресенье для
  // выходных/ВАС). Значение внутри — весь набор полей за эту неделю.
  if (!record.midweekSchedule || typeof record.midweekSchedule !== "object" || Array.isArray(record.midweekSchedule)) record.midweekSchedule = {};
  if (!record.studySchedule || typeof record.studySchedule !== "object" || Array.isArray(record.studySchedule)) record.studySchedule = {};
  if (!record.weekendSchedule || typeof record.weekendSchedule !== "object" || Array.isArray(record.weekendSchedule)) record.weekendSchedule = {};
  if (!record.vpsSchedule || typeof record.vpsSchedule !== "object" || Array.isArray(record.vpsSchedule)) record.vpsSchedule = {};
  // Корзина — сюда попадают удалённые недели вместо безвозвратного стирания,
  // чтобы можно было восстановить при ошибке.
  if (!record.midweekTrash || typeof record.midweekTrash !== "object" || Array.isArray(record.midweekTrash)) record.midweekTrash = {};
  if (!record.studyTrash || typeof record.studyTrash !== "object" || Array.isArray(record.studyTrash)) record.studyTrash = {};
  if (!record.weekendTrash || typeof record.weekendTrash !== "object" || Array.isArray(record.weekendTrash)) record.weekendTrash = {};
  if (!record.vpsTrash || typeof record.vpsTrash !== "object" || Array.isArray(record.vpsTrash)) record.vpsTrash = {};
  // Черновики — рабочие копии каждой таблицы, не влияют на основную,
  // пока их явно не опубликуют.
  if (!record.midweekDraft || typeof record.midweekDraft !== "object" || Array.isArray(record.midweekDraft)) record.midweekDraft = {};
  if (!record.studyDraft || typeof record.studyDraft !== "object" || Array.isArray(record.studyDraft)) record.studyDraft = {};
  if (!record.weekendDraft || typeof record.weekendDraft !== "object" || Array.isArray(record.weekendDraft)) record.weekendDraft = {};
  if (!record.vpsDraft || typeof record.vpsDraft !== "object" || Array.isArray(record.vpsDraft)) record.vpsDraft = {};
  // Заявки на доступ к изменению порядка в своей группе.
  if (!Array.isArray(record.reorderAccessRequests)) record.reorderAccessRequests = [];

  // Если пользователей ещё нет вообще — сеем ОДНОГО супер-админа.
  if (record.users.length === 0 && env.SEED_ADMIN_EMAIL && env.SEED_ADMIN_PASSWORD) {
    const pass = await hashPassword(env.SEED_ADMIN_PASSWORD);
    record.users.push({ email: env.SEED_ADMIN_EMAIL, pass, group: "1", role: "superadmin", approved: true });
    await writeBoard(env, record);
  }

  return record;
}

async function writeBoard(env, data) {
  const gzip = await gzipCompress(JSON.stringify(data));
  await fetchJsonBinWithRetry(`https://api.jsonbin.io/v3/b/${BIN_ID}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Master-Key": env.JSONBIN_KEY },
    body: JSON.stringify({ gzip }),
  });
}

function stripPasswords(users) {
  return (users || []).map((u) => ({
    email: u.email,
    group: u.group,
    role: u.role,
    approved: u.approved === undefined ? true : !!u.approved,
    canReorderOwnGroup: !!u.canReorderOwnGroup,
    canReorderOwnGroupExpiresAt: u.canReorderOwnGroupExpiresAt || null,
  }));
}

// Доступ к изменению порядка в своей группе — либо выдан насовсем, либо
// временно (по заявке с истекающим сроком).
function hasReorderAccess(userRecord) {
  if (!userRecord) return false;
  if (userRecord.canReorderOwnGroup === true) return true;
  if (userRecord.canReorderOwnGroupExpiresAt && Date.now() < userRecord.canReorderOwnGroupExpiresAt) return true;
  return false;
}

/* ============== обработчик запросов ============== */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      // Регистрация
      if (path === "/register" && request.method === "POST") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "").trim();
        const group = String(body.group || "").trim().slice(0, 20);
        if (!email || !password || !group) return json({ error: "Заполните все поля" }, 400);
        const record = await readBoard(env);
        if (record.users.some((u) => u.email.toLowerCase() === email))
          return json({ error: "Пользователь с таким email уже существует" }, 400);
        const pass = await hashPassword(password);
        record.users.push({ email, pass, group, role: "user", approved: false });
        await writeBoard(env, record);
        const token = await signToken({ email, role: "user", group, exp: Date.now() + TOKEN_LIFETIME_MS }, env);
        return json({ token, email, role: "user", group, approved: false });
      }

      // Вход
      if (path === "/login" && request.method === "POST") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "").trim();
        const record = await readBoard(env);
        const user = record.users.find((u) => u.email.toLowerCase() === email);
        if (!user || !(await verifyPassword(password, user.pass))) {
          return json({ error: "Неверный email или пароль" }, 401);
        }
        if (!(typeof user.pass === "string" && user.pass.startsWith("s2$"))) {
          user.pass = await hashPassword(password);
          await writeBoard(env, record);
        }
        const isApproved = user.approved === undefined ? true : !!user.approved;
        const token = await signToken({ email: user.email, role: user.role, group: user.group, exp: Date.now() + TOKEN_LIFETIME_MS }, env);
        return json({ token, email: user.email, role: user.role, group: user.group, approved: isApproved, canReorderOwnGroup: hasReorderAccess(user), scheduleLastSeen: user.scheduleLastSeen || {} });
      }

      // Все запросы ниже требуют входа
      const auth = await getAuthUser(request, env);
      if (!auth) return json({ error: "Требуется вход" }, 401);
      const isAdmin = auth.role === "admin" || auth.role === "superadmin";
      const isSuperadmin = auth.role === "superadmin";

      // Получение данных приложения
      if (path === "/appdata" && request.method === "GET") {
        const record = await readBoard(env);
        return json({
          data: {
            users: isSuperadmin ? stripPasswords(record.users) : [],
            groupRoster: record.groupRoster || [],
            midweekSchedule: record.midweekSchedule || {},
            studySchedule: record.studySchedule || {},
            weekendSchedule: record.weekendSchedule || {},
            vpsSchedule: record.vpsSchedule || {},
            midweekTrash: record.midweekTrash || {},
            studyTrash: record.studyTrash || {},
            weekendTrash: record.weekendTrash || {},
            vpsTrash: record.vpsTrash || {},
            midweekDraft: record.midweekDraft || {},
            studyDraft: record.studyDraft || {},
            weekendDraft: record.weekendDraft || {},
            vpsDraft: record.vpsDraft || {},
            reorderAccessRequests: isSuperadmin ? record.reorderAccessRequests : record.reorderAccessRequests.filter((r) => r.email === auth.email),
          },
          role: auth.role,
          email: auth.email,
          group: auth.group,
        });
      }

      // Сохранение данных приложения
      if (path === "/appdata" && request.method === "PUT") {
        const incoming = await request.json();
        const record = await readBoard(env);

        // Состав групп — полностью редактирует только админ/супер-админ.
        // Обычному пользователю с включённым правом canReorderOwnGroup
        // разрешаем ТОЛЬКО менять порядок номеров внутри его собственной
        // группы — ни группу человека, ни состав других групп он изменить
        // не может, это проверяется здесь построчно, не доверяя клиенту.
        if (Array.isArray(incoming.groupRoster)) {
          if (isAdmin) {
            record.groupRoster = incoming.groupRoster;
          } else {
            const currentUserRecord = record.users.find((u) => u.email === auth.email);
            if (!hasReorderAccess(currentUserRecord)) {
              return json({ error: "Недостаточно прав для изменения состава групп" }, 403);
            }
            const myGroup = String(currentUserRecord.group);
            const oldList = record.groupRoster || [];
            const newList = incoming.groupRoster;
            const oldById = {};
            oldList.forEach((r) => { oldById[r.id] = r; });

            const sameIds = oldList.length === newList.length && oldList.every((r) => newList.some((n) => n.id === r.id));
            let valid = sameIds;
            if (valid) {
              for (const r of newList) {
                const prev = oldById[r.id];
                if (!prev) { valid = false; break; }
                if (String(prev.group) === myGroup) {
                  // Запись из его группы — группу менять нельзя, позицию можно.
                  if (String(r.group) !== myGroup) { valid = false; break; }
                } else {
                  // Запись из чужой группы — должна остаться нетронутой полностью.
                  if (String(r.group) !== String(prev.group) || String(r.position) !== String(prev.position)) { valid = false; break; }
                }
              }
            }

            if (!valid) return json({ error: "Можно менять порядок только внутри своей группы" }, 403);
            record.groupRoster = newList;
          }
        }

        // Расписание встреч (все 4 таблицы) — редактирует только
        // админ/супер-админ, видят все вошедшие. Отмечаем время
        // последнего изменения КАЖДОЙ недели автоматически (не доверяем
        // клиенту) — основа будущей подсветки "свежих" правок.
        const scheduleFields = ["midweekSchedule", "studySchedule", "weekendSchedule", "vpsSchedule", "midweekTrash", "studyTrash", "weekendTrash", "vpsTrash", "midweekDraft", "studyDraft", "weekendDraft", "vpsDraft"];
        for (const field of scheduleFields) {
          if (incoming[field] && typeof incoming[field] === "object" && !Array.isArray(incoming[field])) {
            if (!isAdmin) return json({ error: "Недостаточно прав для изменения расписания" }, 403);
            const now = Date.now();
            const prevDict = record[field] || {};
            const merged = {};
            for (const dateKey of Object.keys(incoming[field])) {
              const incWeek = incoming[field][dateKey];
              const prevWeek = prevDict[dateKey];
              const changed = !prevWeek || JSON.stringify({ ...incWeek, updatedAt: 0, updatedBy: "" }) !== JSON.stringify({ ...prevWeek, updatedAt: 0, updatedBy: "" });
              merged[dateKey] = {
                ...incWeek,
                updatedAt: changed ? now : (prevWeek ? prevWeek.updatedAt : now),
                updatedBy: changed ? auth.email : (prevWeek ? prevWeek.updatedBy : auth.email),
              };
            }
            record[field] = merged;
          }
        }

        // Отметка "просмотрено" для подсветки изменений — ОТДЕЛЬНО для каждой из
        // 4 таблиц (значение markScheduleSeen — название таблицы). Любой
        // вошедший может обновить только СВОЮ отметку.
        const validScheduleTables = ["midweek", "study", "weekend", "vps"];
        if (typeof incoming.markScheduleSeen === "string" && validScheduleTables.includes(incoming.markScheduleSeen)) {
          const userRec = record.users.find((u) => u.email === auth.email);
          if (userRec) {
            if (!userRec.scheduleLastSeen || typeof userRec.scheduleLastSeen !== "object") userRec.scheduleLastSeen = {};
            userRec.scheduleLastSeen[incoming.markScheduleSeen] = Date.now();
          }
        }

        // Заявки на временный доступ к изменению порядка в своей группе.
        // Обычный пользователь может добавить/обновить только СВОЮ заявку.
        // Супер-админ управляет всем списком целиком (одобряет, отклоняет —
        // удаляя запись из массива).
        if (Array.isArray(incoming.reorderAccessRequests)) {
          if (isSuperadmin) {
            record.reorderAccessRequests = incoming.reorderAccessRequests;
          } else {
            const others = record.reorderAccessRequests.filter((r) => r.email !== auth.email);
            const mine = incoming.reorderAccessRequests.filter((r) => r.email === auth.email);
            record.reorderAccessRequests = [...others, ...mine];
          }
        }

        // Пользователи (одобрение регистрации, роли, группы, пароли) —
        // управляет только супер-админ.
        if (Array.isArray(incoming.users)) {
          if (!isSuperadmin) return json({ error: "Недостаточно прав для изменения пользователей" }, 403);
          const byEmail = {};
          record.users.forEach((u) => { byEmail[u.email] = u; });
          const newUsersList = [];
          for (const incUser of incoming.users) {
            if (!incUser.email) continue;
            const existing = byEmail[incUser.email];
            const hasExpiresAtField = Object.prototype.hasOwnProperty.call(incUser, "canReorderOwnGroupExpiresAt");
            if (incUser.pass) {
              const pass = await hashPassword(incUser.pass);
              newUsersList.push({
                email: incUser.email,
                group: incUser.group ?? (existing ? existing.group : "1"),
                role: incUser.role || (existing ? existing.role : "user"),
                approved: incUser.approved ?? (existing ? existing.approved : false),
                canReorderOwnGroup: incUser.canReorderOwnGroup ?? (existing ? existing.canReorderOwnGroup : false),
                canReorderOwnGroupExpiresAt: hasExpiresAtField ? incUser.canReorderOwnGroupExpiresAt : (existing ? existing.canReorderOwnGroupExpiresAt : null),
                pass,
              });
            } else if (existing) {
              newUsersList.push({
                ...existing,
                group: incUser.group ?? existing.group,
                role: incUser.role ?? existing.role,
                approved: incUser.approved ?? existing.approved,
                canReorderOwnGroup: incUser.canReorderOwnGroup ?? existing.canReorderOwnGroup,
                canReorderOwnGroupExpiresAt: hasExpiresAtField ? incUser.canReorderOwnGroupExpiresAt : existing.canReorderOwnGroupExpiresAt,
              });
            }
          }
          record.users = newUsersList;
        }

        await writeBoard(env, record);
        return json({
          data: {
            users: isSuperadmin ? stripPasswords(record.users) : [],
            groupRoster: record.groupRoster || [],
            midweekSchedule: record.midweekSchedule || {},
            studySchedule: record.studySchedule || {},
            weekendSchedule: record.weekendSchedule || {},
            vpsSchedule: record.vpsSchedule || {},
            midweekTrash: record.midweekTrash || {},
            studyTrash: record.studyTrash || {},
            weekendTrash: record.weekendTrash || {},
            vpsTrash: record.vpsTrash || {},
            midweekDraft: record.midweekDraft || {},
            studyDraft: record.studyDraft || {},
            weekendDraft: record.weekendDraft || {},
            vpsDraft: record.vpsDraft || {},
            reorderAccessRequests: isSuperadmin ? record.reorderAccessRequests : record.reorderAccessRequests.filter((r) => r.email === auth.email),
          },
          scheduleLastSeen: (record.users.find((u) => u.email === auth.email) || {}).scheduleLastSeen || {},
        });
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: "Внутренняя ошибка сервера: " + err.message }, 500);
    }
  },
};
