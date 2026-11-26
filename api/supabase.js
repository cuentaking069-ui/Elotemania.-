
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

const ROLES_ADMIN = ["admin", "administrador", "dueno", "dueño", "superadmin"];

function json(res, status, body) {
  return res.status(status).json(body);
}

function serviceHeaders(key) {
  return {
    apikey: key,
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json"
  };
}

function digits(value) {
  return String(value || "").replace(/\D/g, "");
}

function normalizePhone(value) {
  return digits(value).slice(-10);
}

function makeToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
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

  if (actual.length !== expected.length ||
      !crypto.timingSafeEqual(actual, expected)) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString("utf8")
    );

    if (!payload.exp || payload.exp < Date.now() || !payload.sub) return null;
    return payload;
  } catch {
    return null;
  }
}

async function supabaseFetch(url, key, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...serviceHeaders(key),
      ...(options.headers || {})
    }
  });

  const raw = await response.text();
  let data = null;

  try {
    data = raw ? JSON.parse(raw) : null;
  } catch {
    data = { message: raw };
  }

  if (!response.ok) {
    const error = new Error(
      data?.message || data?.error || "Error de Supabase."
    );
    error.status = response.status;
    throw error;
  }

  return data;
}

async function postAction(req, res) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const sessionSecret = process.env.ADMIN_SESSION_SECRET;

  if (!supabaseUrl || !serviceKey) {
    return json(res, 500, {
      error: "Falta configurar SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en Vercel."
    });
  }

  const body = req.body || {};
  const action = body.action;

  // CONSULTAR PUNTOS DEL CLIENTE
  if (action === "customer_points") {
    const whatsapp = digits(body.whatsapp);

    if (normalizePhone(whatsapp).length !== 10) {
      return json(res, 400, {
        error: "Número de WhatsApp no válido."
      });
    }

    const url = new URL(`${supabaseUrl}/rest/v1/clientes`);
    url.searchParams.set(
      "select",
      "nombre,whatsapp,puntos,premios_obtenidos"
    );

    const rows = await supabaseFetch(url.toString(), serviceKey);

    const cliente = (Array.isArray(rows) ? rows : []).find(
      item => normalizePhone(item.whatsapp) === normalizePhone(whatsapp)
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

  // INICIAR SESIÓN DE ADMINISTRADOR
  if (action === "admin_login") {
    if (!sessionSecret) {
      return json(res, 500, {
        error: "Falta configurar ADMIN_SESSION_SECRET en Vercel."
      });
    }

    const usuario = String(body.usuario || "").trim();
    const pin = String(body.pin || "").trim();

    if (!usuario || !pin || pin.length > 64) {
      return json(res, 400, {
        error: "Usuario o PIN no válido."
      });
    }

    const url = new URL(`${supabaseUrl}/rest/v1/usuarios`);
    url.searchParams.set("select", "id,usuario,rol,pin,activo");
    url.searchParams.set("usuario", `eq.${usuario}`);
    url.searchParams.set("activo", "eq.true");
    url.searchParams.set("limit", "1");

    const rows = await supabaseFetch(url.toString(), serviceKey);
    const user = rows?.[0];

    if (
      !user ||
      String(user.pin || "") !== pin ||
      !ROLES_ADMIN.includes(String(user.rol || "").toLowerCase())
    ) {
      return json(res, 401, {
        error: "Credenciales incorrectas o usuario sin permisos de administrador."
      });
    }

    const token = makeToken({
      sub: String(user.id),
      usuario: user.usuario,
      rol: user.rol,
      exp: Date.now() + 8 * 60 * 60 * 1000
    }, sessionSecret);

    return json(res, 200, {
      token,
      usuario: user.usuario
    });
  }

  // CANJEAR PREMIO
  if (action === "admin_redeem") {
    if (!sessionSecret) {
      return json(res, 500, {
        error: "Falta configurar ADMIN_SESSION_SECRET en Vercel."
      });
    }

    const auth = String(req.headers.authorization || "");
    const session = verifyToken(
      auth.replace(/^Bearer\s+/i, ""),
      sessionSecret
    );

    if (
      !session ||
      !ROLES_ADMIN.includes(String(session.rol || "").toLowerCase())
    ) {
      return json(res, 401, {
        error: "Inicia sesión como administrador."
      });
    }

    const whatsapp = digits(body.whatsapp);

    if (normalizePhone(whatsapp).length !== 10) {
      return json(res, 400, {
        error: "Número de WhatsApp no válido."
      });
    }

    const result = await supabaseFetch(
      `${supabaseUrl}/rest/v1/rpc/canjear_premio_puntos`,
      serviceKey,
      {
        method: "POST",
        headers: { Prefer: "return=representation" },
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

  // REGISTRAR VENTA CONFIRMADA
  if (action === "admin_sale") {
    if (!sessionSecret) {
      return json(res, 500, {
        error: "Falta configurar ADMIN_SESSION_SECRET en Vercel."
      });
    }

    const auth = String(req.headers.authorization || "");
    const session = verifyToken(
      auth.replace(/^Bearer\s+/i, ""),
      sessionSecret
    );

    if (
      !session ||
      !ROLES_ADMIN.includes(String(session.rol || "").toLowerCase())
    ) {
      return json(res, 401, {
        error: "Inicia sesión como administrador."
      });
    }

    const nombre = String(body.nombre || "").trim().slice(0, 120);
    const whatsapp = digits(body.whatsapp);
    const total = Number(body.total);

    if (
      !nombre ||
      normalizePhone(whatsapp).length !== 10 ||
      !Number.isFinite(total) ||
      total <= 0 ||
      total > 1000000
    ) {
      return json(res, 400, {
        error: "Datos de venta no válidos."
      });
    }

    const result = await supabaseFetch(
      `${supabaseUrl}/rest/v1/rpc/registrar_venta_punto`,
      serviceKey,
      {
        method: "POST",
        headers: { Prefer: "return=representation" },
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

  return json(res, 400, {
    error: "Acción no reconocida."
  });
}

export default async function handler(req, res) {
  const supabaseUrl = process.env.SUPABASE_URL;

  if (!supabaseUrl) {
    return json(res, 500, {
      error: "Falta SUPABASE_URL en Vercel."
    });
  }

  try {
    if (req.method === "POST") {
      return await postAction(req, res);
    }

    if (req.method !== "GET") {
      return json(res, 405, {
        error: "Método no permitido."
      });
    }

    // CONSULTA GET QUE UTILIZA EL MENÚ
    const supabaseKey = process.env.SUPABASE_ANON_KEY;

    if (!supabaseKey) {
      return json(res, 500, {
        error: "Falta SUPABASE_ANON_KEY en Vercel."
      });
    }

    const table = req.query.table;

    if (!table) {
      return json(res, 400, {
        error: "Falta indicar la tabla."
      });
    }

    if (!TABLES.includes(table)) {
      return json(res, 400, {
        error: "Tabla no permitida."
      });
    }

    const url = new URL(`${supabaseUrl}/rest/v1/${table}`);

    for (const key of GET_PARAMS) {
      if (req.query[key] !== undefined) {
        url.searchParams.set(key, req.query[key]);
      }
    }

    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        apikey: supabaseKey,
        Authorization: `Bearer ${supabaseKey}`,
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

