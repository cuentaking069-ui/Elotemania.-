
import crypto from "crypto";

const TABLES = [
  "productos",
  "configuracion",
  "clientes",
  "ventas",
  "detalle_ventas",
  "cierres_turno",
  "usuarios"
];

const GET_PARAMS = [
  "select", "order", "limit", "offset", "id", "activo",
  "whatsapp", "corte_id", "venta_id", "cliente_id",
  "usuario", "rol", "nombre", "categoria"
];

function json(res, status, body) {
  return res.status(status).json(body);
}

function digits(value) {
  return String(value || "").replace(/\D/g, "");
}

function normalizePhone(value) {
  return digits(value).slice(-10);
}

function headers(key) {
  return {
    apikey: key,
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json"
  };
}

async function supabaseFetch(url, key, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { ...headers(key), ...(options.headers || {}) }
  });

  const raw = await response.text();
  let data;

  try {
    data = raw ? JSON.parse(raw) : null;
  } catch {
    data = { message: raw };
  }

  if (!response.ok) {
    const error = new Error(data?.message || data?.error || "Error de Supabase");
    error.status = response.status;
    throw error;
  }

  return data;
}

function makeToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${signature}`;
}

function verifyToken(token, secret) {
  if (!token || !secret) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const expected = crypto.createHmac("sha256", secret).update(parts[0]).digest();
  let actual;

  try {
    actual = Buffer.from(parts[1], "base64url");
  } catch {
    return null;
  }

  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (!payload.exp || payload.exp < Date.now() || !payload.sub) return null;
    return payload;
  } catch {
    return null;
  }
}

async function postAction(req, res) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!supabaseUrl || !serviceKey) {
    return json(res, 500, {
      error: "Falta SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en Vercel."
    });
  }

  const body = req.body || {};
  const action = body.action;

  // CONSULTAR PUNTOS DEL CLIENTE
  if (action === "customer_points") {
    const whatsapp = digits(body.whatsapp);

    if (normalizePhone(whatsapp).length !== 10) {
      return json(res, 400, { error: "Escribe un WhatsApp válido." });
    }

    const url = new URL(`${supabaseUrl}/rest/v1/clientes`);
    url.searchParams.set("select", "nombre,whatsapp,puntos,premios_obtenidos");

    const clientes = await supabaseFetch(url.toString(), serviceKey);

    const cliente = (clientes || []).find(
      c => normalizePhone(c.whatsapp) === normalizePhone(whatsapp)
    );

    if (!cliente) {
      return json(res, 200, { found: false });
    }

    return json(res, 200, {
      found: true,
      nombre: cliente.nombre || "Cliente",
      puntos: Number(cliente.puntos || 0),
      premios_obtenidos: Number(cliente.premios_obtenidos || 0)
    });
  }

  // INICIAR SESIÓN ADMIN
  if (action === "admin_login") {
    if (!secret) {
      return json(res, 500, { error: "Falta ADMIN_SESSION_SECRET en Vercel." });
    }

    const usuario = String(body.usuario || "").trim();
    const pin = String(body.pin || "").trim();

    if (!usuario || !pin) {
      return json(res, 400, { error: "Completa usuario y PIN." });
    }

    const url = new URL(`${supabaseUrl}/rest/v1/usuarios`);
    url.searchParams.set("select", "id,usuario,rol,pin,activo");
    url.searchParams.set("usuario", `eq.${usuario}`);
    url.searchParams.set("activo", "eq.true");
    url.searchParams.set("limit", "1");

    const users = await supabaseFetch(url.toString(), serviceKey);
    const user = users?.[0];

    const roles = ["admin", "administrador", "dueno", "dueño"];

    if (
      !user ||
      user.pin !== pin ||
      !roles.includes(String(user.rol || "").toLowerCase())
    ) {
      return json(res, 401, { error: "Usuario o PIN incorrectos." });
    }

    const token = makeToken({
      sub: String(user.id),
      usuario: user.usuario,
      rol: user.rol,
      exp: Date.now() + 8 * 60 * 60 * 1000
    }, secret);

    return json(res, 200, { token, usuario: user.usuario });
  }

  // REGISTRAR VENTA CONFIRMADA
  if (action === "admin_sale") {
    if (!secret) {
      return json(res, 500, { error: "Falta ADMIN_SESSION_SECRET en Vercel." });
    }

    const auth = String(req.headers.authorization || "");
    const session = verifyToken(auth.replace(/^Bearer\s+/i, ""), secret);

    if (!session || !["admin", "administrador", "dueno", "dueño"].includes(String(session.rol || "").toLowerCase())) {
      return json(res, 401, { error: "Inicia sesión como administrador." });
    }

    const nombre = String(body.nombre || "").trim().slice(0, 120);
    const whatsapp = digits(body.whatsapp);
    const total = Number(body.total);

    if (!nombre || normalizePhone(whatsapp).length !== 10 || !Number.isFinite(total) || total <= 0) {
      return json(res, 400, { error: "Datos de venta no válidos." });
    }

    const result = await supabaseFetch(
      `${supabaseUrl}/rest/v1/rpc/registrar_venta_punto`,
      serviceKey,
      {
        method: "POST",
        body: JSON.stringify({
          p_nombre: nombre,
          p_whatsapp: whatsapp,
          p_total: total,
          p_usuario_id: Number(session.sub)
        })
      }
    );

    const row = Array.isArray(result) ? result[0] : result;

    return json(res, 200, {
      ok: true,
      nombre: row?.nombre || nombre,
      puntos: row?.puntos ?? null,
      venta_id: row?.venta_id ?? null
    });
  }

  // CANJEAR PREMIO
  if (action === "admin_redeem") {
    if (!secret) {
      return json(res, 500, { error: "Falta ADMIN_SESSION_SECRET en Vercel." });
    }

    const auth = String(req.headers.authorization || "");
    const session = verifyToken(auth.replace(/^Bearer\s+/i, ""), secret);

    if (!session || !["admin", "administrador", "dueno", "dueño"].includes(String(session.rol || "").toLowerCase())) {
      return json(res, 401, { error: "Inicia sesión como administrador." });
    }

    const whatsapp = digits(body.whatsapp);

    if (normalizePhone(whatsapp).length !== 10) {
      return json(res, 400, { error: "WhatsApp no válido." });
    }

    const result = await supabaseFetch(
      `${supabaseUrl}/rest/v1/rpc/canjear_premio_puntos`,
      serviceKey,
      {
        method: "POST",
        body: JSON.stringify({ p_whatsapp: whatsapp })
      }
    );

    const row = Array.isArray(result) ? result[0] : result;

    return json(res, 200, {
      ok: true,
      nombre: row?.nombre || "Cliente",
      puntos: row?.puntos ?? 0,
      premios_obtenidos: row?.premios_obtenidos ?? 0
    });
  }

  return json(res, 400, { error: "Acción no reconocida." });
}

export default async function handler(req, res) {
  const supabaseUrl = process.env.SUPABASE_URL;

  if (!supabaseUrl) {
    return json(res, 500, { error: "Falta SUPABASE_URL en Vercel." });
  }

  try {
    if (req.method === "POST") {
      return await postAction(req, res);
    }

    if (req.method !== "GET") {
      return json(res, 405, { error: "Método no permitido." });
    }

    // CONSULTAS DEL MENÚ
    const key = process.env.SUPABASE_ANON_KEY;

    if (!key) {
      return json(res, 500, { error: "Falta SUPABASE_ANON_KEY en Vercel." });
    }

    const table = req.query.table;

    if (!table) {
      return json(res, 400, { error: "Falta indicar la tabla." });
    }

    if (!TABLES.includes(table)) {
      return json(res, 400, { error: "Tabla no permitida." });
    }

    const url = new URL(`${supabaseUrl}/rest/v1/${table}`);

    for (const param of GET_PARAMS) {
      if (req.query[param] !== undefined) {
        url.searchParams.set(param, req.query[param]);
      }
    }

    const response = await fetch(url.toString(), {
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json"
      }
    });

    const raw = await response.text();
    let data;

    try {
      data = raw ? JSON.parse(raw) : null;
    } catch {
      return json(res, response.status, {
        error: "Supabase no devolvió JSON.",
        detalle: raw
      });
    }

    return json(res, response.status, data);

  } catch (error) {
    return json(res, error.status || 500, {
      error: error.message || "Error conectando con Supabase."
    });
  }
}

