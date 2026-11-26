
const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET;

const TABLES = [
  "productos",
  "configuracion",
  "clientes",
  "ventas",
  "detalle_ventas",
  "cierres_turno",
  "usuarios"
];

function send(res, status, data) {
  return res.status(status).json(data);
}

async function supabase(path, options = {}, service = false) {
  const key = service ? SERVICE_KEY : ANON_KEY;

  const response = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    throw new Error(
      typeof data === "string" ? data : JSON.stringify(data)
    );
  }

  return data;
}

function createToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(data)
    .digest("base64url");

  return `${data}.${signature}`;
}

function verifyToken(token) {
  if (!SESSION_SECRET || !token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(parts[0])
    .digest();

  let actual;
  try {
    actual = Buffer.from(parts[1], "base64url");
  } catch {
    return null;
  }

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );

    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

module.exports = async (req, res) => {
  try {
    if (!SUPABASE_URL || !ANON_KEY) {
      return send(res, 500, { error: "Falta configurar Supabase en Vercel" });
    }

    // CONSULTAS DEL MENÚ
    if (req.method === "GET") {
      const table = req.query.table;

      if (!TABLES.includes(table)) {
        return send(res, 400, { error: "Tabla no permitida" });
      }

      const params = new URLSearchParams();

      for (const [key, value] of Object.entries(req.query)) {
        if (key !== "table" && typeof value === "string") {
          params.set(key, value);
        }
      }

      const data = await supabase(
        `${table}?${params.toString()}`,
        {},
        false
      );

      return send(res, 200, data);
    }

    if (req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return send(res, 405, { error: "Método no permitido" });
    }

    if (!SERVICE_KEY) {
      return send(res, 500, { error: "Falta SUPABASE_SERVICE_ROLE_KEY en Vercel" });
    }

    const body = req.body || {};
    const action = body.action;

// CONSULTAR PUNTOS DEL CLIENTE
if (action === "customer_points") {
  const whatsapp = String(body.whatsapp || "").replace(/\D/g, "");

  if (!whatsapp) {
    return send(res, 400, { error: "Escribe tu WhatsApp" });
  }

  const clientes = await supabase(
    "clientes?select=nombre,whatsapp,puntos,premios_obtenidos",
    {},
    true
  );

  const normalizar = numero =>
    String(numero || "").replace(/\D/g, "").slice(-10);

  const cliente = clientes.find(
    c => normalizar(c.whatsapp) === normalizar(whatsapp)
  );

  if (!cliente) {
    return send(res, 200, { found: false });
  }

  return send(res, 200, {
    found: true,
    nombre: cliente.nombre,
    puntos: Number(cliente.puntos || 0),
    premios_obtenidos: Number(cliente.premios_obtenidos || 0)
  });
}


      const token = createToken({
        id: user.id,
        usuario: user.usuario,
        exp: Date.now() + 8 * 60 * 60 * 1000
      });

      return send(res, 200, {
        ok: true,
        token,
        nombre: user.nombre || user.usuario
      });
    }

    // VALIDAR SESIÓN DE ADMIN
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const admin = verifyToken(token);

    if (!admin) {
      return send(res, 401, { error: "Sesión vencida. Inicia sesión nuevamente." });
    }

    // REGISTRAR COMPRA Y OTORGAR 1 PUNTO
    if (action === "admin_sale") {
      const nombre = String(body.nombre || "").trim();
      const whatsapp = String(body.whatsapp || "").replace(/\D/g, "");
      const total = Number(body.total);

      if (!nombre || !whatsapp || !Number.isFinite(total) || total <= 0) {
        return send(res, 400, { error: "Revisa nombre, WhatsApp y total de la compra" });
      }

      const result = await supabase("rpc/registrar_venta_punto", {
        method: "POST",
        body: JSON.stringify({
          p_nombre: nombre,
          p_whatsapp: whatsapp,
          p_total: total,
          p_usuario_id: admin.id
        })
      }, true);

      return send(res, 200, { ok: true, resultado: result });
    }

    // CANJEAR 10 PUNTOS POR UN ELOTE
    if (action === "admin_redeem") {
      const whatsapp = String(body.whatsapp || "").replace(/\D/g, "");

      if (!whatsapp) {
        return send(res, 400, { error: "Escribe el WhatsApp del cliente" });
      }

      const result = await supabase("rpc/canjear_premio_puntos", {
        method: "POST",
        body: JSON.stringify({ p_whatsapp: whatsapp })
      }, true);

      return send(res, 200, { ok: true, resultado: result });
    }

    return send(res, 400, { error: "Acción no reconocida" });

  } catch (error) {
    console.error("Error API Elotemanía:", error);
    return send(res, 500, { error: "Error en la API", detalle: error.message });
  }
};

