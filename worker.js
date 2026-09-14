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

const BIN_ID = "ВПИШИТЕ_СЮДА_ВАШ_BIN_ID"; // <-- заменить перед деплоем
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

async function fetchJsonBinWithRetry(url, options, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return res;
      lastErr = new Error(`JSONBin временно недоступен (код ${res.status})`);
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
  // Задания по теократии: [{ id, group, position, title, description,
  // date, createdAt, updatedAt, updatedBy }]. position может быть пустым —
  // тогда задание общее на группу, а не на конкретное место в ней.
  if (!Array.isArray(record.assignments)) record.assignments = [];

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
    assignmentsLastSeenAt: u.assignmentsLastSeenAt || 0,
  }));
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
        record.users.push({ email, pass, group, role: "user", approved: false, assignmentsLastSeenAt: 0 });
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
        return json({ token, email: user.email, role: user.role, group: user.group, approved: isApproved, assignmentsLastSeenAt: user.assignmentsLastSeenAt || 0 });
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
            assignments: record.assignments || [],
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

        // Состав групп — редактирует только админ/супер-админ.
        if (Array.isArray(incoming.groupRoster)) {
          if (!isAdmin) return json({ error: "Недостаточно прав для изменения состава групп" }, 403);
          record.groupRoster = incoming.groupRoster;
        }

        // Задания по теократии — создавать/редактировать может только
        // админ/супер-админ. Отмечаем время последнего изменения автоматически
        // (не доверяем клиенту в этом поле) — это и есть основа подсветки
        // "свежих" изменений у ответственных за группы.
        if (Array.isArray(incoming.assignments)) {
          if (!isAdmin) return json({ error: "Недостаточно прав для изменения заданий" }, 403);
          const now = Date.now();
          const prevById = {};
          (record.assignments || []).forEach((a) => { prevById[a.id] = a; });
          record.assignments = incoming.assignments.map((a) => {
            const prev = prevById[a.id];
            const changed = !prev
              || prev.title !== a.title
              || prev.description !== a.description
              || prev.date !== a.date
              || prev.group !== a.group
              || prev.position !== a.position;
            return {
              ...a,
              createdAt: prev ? prev.createdAt : now,
              updatedAt: changed ? now : (prev ? prev.updatedAt : now),
              updatedBy: changed ? auth.email : (prev ? prev.updatedBy : auth.email),
            };
          });
        }

        // Отметка "просмотрено" для подсветки — каждый вошедший может
        // обновлять только СВОЮ отметку времени последнего просмотра заданий.
        if (incoming.markAssignmentsSeen === true) {
          const userRec = record.users.find((u) => u.email === auth.email);
          if (userRec) userRec.assignmentsLastSeenAt = Date.now();
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
            if (incUser.pass) {
              const pass = await hashPassword(incUser.pass);
              newUsersList.push({
                email: incUser.email,
                group: incUser.group ?? (existing ? existing.group : "1"),
                role: incUser.role || (existing ? existing.role : "user"),
                approved: incUser.approved ?? (existing ? existing.approved : false),
                assignmentsLastSeenAt: existing ? existing.assignmentsLastSeenAt : 0,
                pass,
              });
            } else if (existing) {
              newUsersList.push({
                ...existing,
                group: incUser.group ?? existing.group,
                role: incUser.role ?? existing.role,
                approved: incUser.approved ?? existing.approved,
              });
            }
          }
          record.users = newUsersList;
        }

        await writeBoard(env, record);
        const userRecFinal = record.users.find((u) => u.email === auth.email);
        return json({
          data: {
            users: isSuperadmin ? stripPasswords(record.users) : [],
            groupRoster: record.groupRoster || [],
            assignments: record.assignments || [],
          },
          assignmentsLastSeenAt: userRecFinal ? userRecFinal.assignmentsLastSeenAt : 0,
        });
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: "Внутренняя ошибка сервера: " + err.message }, 500);
    }
  },
};
