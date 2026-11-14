import http from "http";
import crypto from "crypto";
import { promisify } from "util";
import { WebSocketServer } from "ws";
import express from "express";
import cors from "cors";
import pg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const {
  DATABASE_URL,
  JWT_SECRET,
  ADMIN_USER,
  ADMIN_PASS,
  PORT = 3000,
  CORS_ORIGIN,
} = process.env;

const SERVERLESS = !!process.env.VERCEL;

if (!DATABASE_URL || !JWT_SECRET || !ADMIN_USER || !ADMIN_PASS) {
  throw new Error("Set DATABASE_URL, JWT_SECRET, ADMIN_USER, ADMIN_PASS");
}

const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  max: SERVERLESS ? 3 : 20,
  connectionTimeoutMillis: 15000,
  idleTimeoutMillis: 30000,
  ssl: /@(localhost|127\.0\.0\.1)/.test(DATABASE_URL)
    ? false
    : { rejectUnauthorized: false },
});

pool.on("error", (e) => console.error("pg", e.message));

const q = (s, p) => pool.query(s, p).then((r) => r.rows);

// DATABASE INITIALIZATION
const INIT_SQL = `
CREATE TABLE IF NOT EXISTS polls(
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  active BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS records(
  id SERIAL PRIMARY KEY,
  poll_id INT REFERENCES polls ON DELETE CASCADE,
  label TEXT NOT NULL,
  pos INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS journeys(
  id SERIAL PRIMARY KEY,
  poll_id INT REFERENCES polls ON DELETE CASCADE,
  date DATE NOT NULL,
  source TEXT,
  destination TEXT,
  direction TEXT DEFAULT 'onward',
  status TEXT DEFAULT 'planned',
  current_record_id INT REFERENCES records ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS messages(
  id SERIAL PRIMARY KEY,
  sender TEXT NOT NULL,
  sender_key TEXT NOT NULL,
  body TEXT NOT NULL,
  edited BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE journeys ADD COLUMN IF NOT EXISTS reached_at TIMESTAMPTZ;
ALTER TABLE journeys ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;

ALTER TABLE records ADD COLUMN IF NOT EXISTS is_pickup BOOLEAN DEFAULT FALSE;
ALTER TABLE records ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT 'onward';

ALTER TABLE polls ADD COLUMN IF NOT EXISTS active_onward BOOLEAN;
ALTER TABLE polls ADD COLUMN IF NOT EXISTS active_return BOOLEAN;

UPDATE polls
SET
  active_onward = COALESCE(active_onward, active, FALSE),
  active_return = COALESCE(active_return, active, FALSE)
WHERE active_onward IS NULL OR active_return IS NULL;

ALTER TABLE polls ALTER COLUMN active_onward SET DEFAULT FALSE;
ALTER TABLE polls ALTER COLUMN active_return SET DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS route_spots(
  id SERIAL PRIMARY KEY,
  direction TEXT NOT NULL,
  label TEXT NOT NULL,
  pos INT NOT NULL DEFAULT 0,
  is_pickup BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS r_poll ON records(poll_id,pos);
CREATE INDEX IF NOT EXISTS j_poll ON journeys(poll_id,date);
`;

// DATABASE INITIALIZATION RETRY
let ready = null;

const initDb = () =>
  (ready ||= q(INIT_SQL).catch((e) => {
    ready = null;
    console.error("db init failed:", e.message);
    throw e;
  }));

initDb().catch(() => {});

// EXPRESS APP
const app = express();

// CORS
const allowed = (CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim().replace(/\/+$/, ""))
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) =>
      cb(
        null,
        !origin ||
          !allowed.length ||
          allowed.includes(origin) ||
          /^https:\/\/bus-tracker[a-z0-9-]*\.vercel\.app$/.test(origin),
      ),
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    maxAge: 86400,
  }),
);

app.use(express.json({ limit: "2mb" }));

// DATABASE MIDDLEWARE
app.use((req, res, next) =>
  initDb().then(
    () => next(),
    (e) =>
      res.status(500).json({
        error: "Database init failed: " + e.message,
      }),
  ),
);

// ERROR HANDLER
const h = (f) => (req, res) =>
  f(req, res).catch((e) =>
    res.status(e.code === "23505" ? 409 : 500).json({
      error: e.code === "23505" ? "Name or username already exists" : e.message,
    }),
  );

// AUTHENTICATION
const auth = (req, res, next) => {
  try {
    req.user = jwt.verify(
      (req.headers.authorization || "").slice(7) || req.query.token,
      JWT_SECRET,
    );
    next();
  } catch {
    res.status(401).json({ error: "Please sign in" });
  }
};

const admin = (req, res, next) =>
  req.user.role === "admin"
    ? next()
    : res.status(403).json({ error: "Admin only" });

// PASSWORD HASHING
const scrypt = promisify(crypto.scrypt);

const hashPw = async (p) => {
  const s = crypto.randomBytes(16).toString("hex");
  return s + ":" + (await scrypt(p, s, 32)).toString("hex");
};

const checkPw = async (p, h) => {
  if (h.startsWith("$2")) return bcrypt.compare(p, h);

  const [s, k] = h.split(":");

  return crypto.timingSafeEqual(await scrypt(p, s, 32), Buffer.from(k, "hex"));
};

// SPOT ORDERING HELPERS
const reorder = (t, ids) =>
  q(
    `UPDATE ${t} x
     SET pos=o.n
     FROM unnest($1::int[]) WITH ORDINALITY o(id,n)
     WHERE x.id=o.id`,
    [ids],
  );

const scopeOf = (t, pollId, dir) =>
  t === "records"
    ? ["poll_id=$1 AND direction=$2", [pollId, dir]]
    : ["direction=$1", [dir]];

async function addSpots(t, pollId, dir, labels, position) {
  const [w, vals] = scopeOf(t, pollId, dir);

  const ex = (
    await q(`SELECT id FROM ${t} WHERE ${w} ORDER BY pos,id`, vals)
  ).map((r) => r.id);

  const ins = await q(
    t === "records"
      ? `INSERT INTO records(poll_id,direction,label,pos)
         SELECT $1,$2,l,0
         FROM unnest($3::text[]) WITH ORDINALITY x(l,o)
         ORDER BY o
         RETURNING id`
      : `INSERT INTO route_spots(direction,label,pos)
         SELECT $1,l,0
         FROM unnest($2::text[]) WITH ORDINALITY x(l,o)
         ORDER BY o
         RETURNING id`,
    [...vals, labels],
  );

  const k = position > 0 ? Math.min(position - 1, ex.length) : ex.length;

  await reorder(t, [
    ...ex.slice(0, k),
    ...ins.map((r) => r.id).sort((a, b) => a - b),
    ...ex.slice(k),
  ]);
}

async function moveSpot(t, id, position) {
  const [r] = await q(
    t === "records"
      ? "SELECT poll_id,direction FROM records WHERE id=$1"
      : "SELECT direction FROM route_spots WHERE id=$1",
    [id],
  );

  if (!r) return;

  const [w, vals] = scopeOf(t, r.poll_id, r.direction);

  const ex = (await q(`SELECT id FROM ${t} WHERE ${w} ORDER BY pos,id`, vals))
    .map((x) => x.id)
    .filter((x) => x !== +id);

  ex.splice(Math.max(0, Math.min(position - 1, ex.length)), 0, +id);

  await reorder(t, ex);
}

// JOURNEY SPOTS
const spotsFor = async (c, id, dir) => {
  let { rows } = await c.query(
    "SELECT id,label FROM records WHERE poll_id=$1 AND direction=$2 ORDER BY pos,id",
    [id, dir],
  );

  if (!rows.length && dir === "return") {
    rows = (
      await c.query(
        `SELECT id,label
         FROM records
         WHERE poll_id=$1 AND direction='onward'
         ORDER BY pos,id`,
        [id],
      )
    ).rows.reverse();
  }

  return rows;
};

// ACTIVATION HELPERS
const dirOf = (d) => (d === "return" ? "return" : "onward");

const actCol = (d) =>
  dirOf(d) === "return" ? "active_return" : "active_onward";

const sign = (u) => jwt.sign(u, JWT_SECRET, { expiresIn: "12h" });

// WEBSOCKET
const server = http.createServer(app);

server.keepAliveTimeout = 65000;

const wss = new WebSocketServer({
  server,
  path: "/ws",
  maxPayload: 1024,
});

const clients = new Set();

wss.on("connection", (ws, req) => {
  try {
    jwt.verify(
      new URL(req.url, "http://x").searchParams.get("token"),
      JWT_SECRET,
    );
  } catch {
    return ws.close(4401);
  }

  ws.alive = true;

  ws.on("pong", () => (ws.alive = true));
  ws.on("error", () => {});

  clients.add(ws);

  ws.on("close", () => clients.delete(ws));
});

if (!SERVERLESS) {
  setInterval(
    () =>
      clients.forEach((ws) => {
        if (!ws.alive) return ws.terminate();

        ws.alive = false;
        ws.ping();
      }),
    25000,
  );
}

let ver = 0;
let cache = null;

const push = (ev, data = {}) => {
  if (ev === "state") ver++;

  const m = JSON.stringify({ ev, data });

  clients.forEach((c) => c.readyState === 1 && c.send(m));
};

// LOGIN
app.post(
  "/api/login",
  h(async (req, res) => {
    const { username = "", password = "" } = req.body;

    if (username === ADMIN_USER && password === ADMIN_PASS) {
      const u = {
        role: "admin",
        name: "Admin",
        key: "admin",
      };

      return res.json({
        token: sign(u),
        user: u,
      });
    }

    const [p] = await q("SELECT * FROM polls WHERE username=$1", [username]);

    if (!p || !(await checkPw(password, p.password_hash))) {
      return res.status(401).json({
        error: "Wrong username or password",
      });
    }

    const u = {
      role: "poll",
      pollId: p.id,
      name: p.name,
      key: "p" + p.id,
    };

    res.json({
      token: sign(u),
      user: u,
    });
  }),
);

// VERSIONED SNAPSHOT
const snapshot = () => {
  if (cache && cache.v === ver && (!SERVERLESS || Date.now() - cache.t < 800)) {
    return cache.p;
  }

  const v = ver;

  const p = Promise.all([
    q(
      "SELECT id,name,username,active,active_onward,active_return FROM polls ORDER BY id",
    ),

    q(
      "SELECT id,poll_id,label,pos,is_pickup,direction FROM records ORDER BY pos,id",
    ),

    q(
      "SELECT id,direction,label,pos,is_pickup FROM route_spots ORDER BY pos,id",
    ),

    // IMPORTANT: started_at is included here
    q(
      `SELECT
        id,
        poll_id,
        to_char(date,'YYYY-MM-DD') date,
        source,
        destination,
        direction,
        status,
        current_record_id,
        reached_at,
        started_at
       FROM journeys
       ORDER BY date,id`,
    ),
  ]);

  cache = {
    v,
    p,
    t: Date.now(),
  };

  p.catch(() => {
    if (cache?.p === p) cache = null;
  });

  return p;
};

// STATE API
app.get(
  "/api/state",
  auth,
  h(async (req, res) => {
    const [polls, records, tpl, journeys] = await snapshot();

    const adm = req.user.role === "admin";

    res.json({
      templates: adm
        ? {
            onward: tpl.filter((t) => t.direction === "onward"),
            return: tpl.filter((t) => t.direction === "return"),
          }
        : undefined,

      polls: polls.map((p) => ({
        ...p,
        username: adm ? p.username : undefined,
        records: records.filter((r) => r.poll_id === p.id),
        journeys: journeys.filter((j) => j.poll_id === p.id),
      })),
    });
  }),
);

// POLLS CRUD
app.post(
  "/api/polls",
  auth,
  admin,
  h(async (req, res) => {
    const list = req.body.polls || [req.body];

    let n = 0;

    for (const p of list) {
      if (!p.name || !p.username || !p.password) continue;

      const [np] = await q(
        `INSERT INTO polls(name,username,password_hash)
         VALUES($1,$2,$3)
         RETURNING id`,
        [p.name.trim(), p.username.trim(), await hashPw(p.password)],
      );

      await q(
        `INSERT INTO records(poll_id,label,pos,is_pickup,direction)
         SELECT $1,label,pos,is_pickup,direction
         FROM route_spots`,
        [np.id],
      );

      n++;
    }

    push("state");

    res.json({ added: n });
  }),
);

app.post(
  "/api/polls/activate",
  auth,
  admin,
  h(async (req, res) => {
    const d = req.body.direction;

    const set = d ? `${actCol(d)}=$2` : "active_onward=$2,active_return=$2";

    await q(
      `UPDATE polls
       SET ${set},
       active=${
         d
           ? `(${d === "return" ? "active_onward" : "$2"} OR ${
               d === "return" ? "$2" : "active_return"
             })`
           : "$2"
       }
       WHERE id=ANY($1::int[])`,
      [(req.body.ids || []).map(Number), !!req.body.active],
    );

    push("state");

    res.json({ ok: 1 });
  }),
);

app.put(
  "/api/polls/:id",
  auth,
  admin,
  h(async (req, res) => {
    const { name, username, password, active } = req.body;

    await q(
      `UPDATE polls
       SET
         name=COALESCE($2,name),
         username=COALESCE($3,username),
         password_hash=COALESCE($4,password_hash),
         active=COALESCE($5,active),
         active_onward=COALESCE($5,active_onward),
         active_return=COALESCE($5,active_return)
       WHERE id=$1`,
      [
        req.params.id,
        name,
        username,
        password ? await hashPw(password) : null,
        active,
      ],
    );

    push("state");

    res.json({ ok: 1 });
  }),
);

app.delete(
  "/api/polls/:id",
  auth,
  admin,
  h(async (req, res) => {
    await q("DELETE FROM polls WHERE id=$1", [req.params.id]);

    push("state");

    res.json({ ok: 1 });
  }),
);

// BUS RECORDS
app.post(
  "/api/polls/:id/records",
  auth,
  admin,
  h(async (req, res) => {
    const labels = (req.body.labels || [])
      .map((l) => String(l).trim())
      .filter(Boolean);

    const dir = req.body.direction === "return" ? "return" : "onward";

    if (labels.length) {
      await addSpots(
        "records",
        +req.params.id,
        dir,
        labels,
        +req.body.position || 0,
      );
    }

    push("state");

    res.json({ added: labels.length });
  }),
);

app.put(
  "/api/records/:id",
  auth,
  admin,
  h(async (req, res) => {
    await q(
      `UPDATE records
       SET
         label=COALESCE($2,label),
         is_pickup=COALESCE($3,is_pickup)
       WHERE id=$1`,
      [req.params.id, req.body.label, req.body.is_pickup],
    );

    if (+req.body.position > 0) {
      await moveSpot("records", req.params.id, +req.body.position);
    }

    push("state");

    res.json({ ok: 1 });
  }),
);

app.delete(
  "/api/records/:id",
  auth,
  admin,
  h(async (req, res) => {
    await q("DELETE FROM records WHERE id=$1", [req.params.id]);

    push("state");

    res.json({ ok: 1 });
  }),
);

// SHARED ROUTE TEMPLATES
const fillEmpty = (dir) =>
  q(
    `INSERT INTO records(poll_id,label,pos,is_pickup,direction)
     SELECT p.id,t.label,t.pos,t.is_pickup,t.direction
     FROM polls p
     CROSS JOIN route_spots t
     WHERE t.direction=$1
     AND NOT EXISTS (
       SELECT 1
       FROM records r
       WHERE r.poll_id=p.id AND r.direction=$1
     )`,
    [dir],
  );

app.post(
  "/api/templates",
  auth,
  admin,
  h(async (req, res) => {
    const dir = req.body.direction === "return" ? "return" : "onward";

    const labels = (req.body.labels || [])
      .map((l) => String(l).trim())
      .filter(Boolean);

    if (!labels.length) {
      return res.status(400).json({
        error: "No spots found",
      });
    }

    if (req.body.replace) {
      await q("DELETE FROM route_spots WHERE direction=$1", [dir]);
    }

    await addSpots("route_spots", null, dir, labels, 0);

    await fillEmpty(dir);

    push("state");

    res.json({ added: labels.length });
  }),
);

app.put(
  "/api/templates/:id",
  auth,
  admin,
  h(async (req, res) => {
    await q(
      `UPDATE route_spots
       SET
         label=COALESCE($2,label),
         is_pickup=COALESCE($3,is_pickup)
       WHERE id=$1`,
      [req.params.id, req.body.label, req.body.is_pickup],
    );

    if (+req.body.position > 0) {
      await moveSpot("route_spots", req.params.id, +req.body.position);
    }

    push("state");

    res.json({ ok: 1 });
  }),
);

app.delete(
  "/api/templates/:id",
  auth,
  admin,
  h(async (req, res) => {
    await q("DELETE FROM route_spots WHERE id=$1", [req.params.id]);

    push("state");

    res.json({ ok: 1 });
  }),
);

app.post(
  "/api/templates/apply",
  auth,
  admin,
  h(async (req, res) => {
    const dir = req.body.direction === "return" ? "return" : "onward";

    const [{ n }] = await q(
      `SELECT count(*)::int n
       FROM polls p
       WHERE EXISTS (
         SELECT 1
         FROM journeys j
         WHERE j.poll_id=p.id AND j.status='active'
       )`,
    );

    await q(
      `DELETE FROM records
       WHERE direction=$1
       AND poll_id IN (
         SELECT id
         FROM polls p
         WHERE NOT EXISTS (
           SELECT 1
           FROM journeys j
           WHERE j.poll_id=p.id AND j.status='active'
         )
       )`,
      [dir],
    );

    await fillEmpty(dir);

    push("state");

    res.json({ skipped: n });
  }),
);

// JOURNEYS CRUD
app.post(
  "/api/journeys",
  auth,
  admin,
  h(async (req, res) => {
    const { poll_id, poll_ids, date, source, destination } = req.body;

    const dir = req.body.direction === "return" ? "return" : "onward";

    const ids = (poll_ids || [poll_id]).map(Number).filter(Boolean);

    if (!ids.length || !date || !source?.trim() || !destination?.trim()) {
      return res.status(400).json({
        error: "Choose buses, date, source and destination",
      });
    }

    const r = await q(
      `INSERT INTO journeys(
         poll_id,date,source,destination,direction
       )
       SELECT p,$2,$3,$4,$5
       FROM unnest($1::int[]) p
       WHERE NOT EXISTS (
         SELECT 1
         FROM journeys j
         WHERE j.poll_id=p
         AND j.date=$2
         AND j.direction=$5
         AND j.status IN ('planned','active')
       )
       RETURNING id`,
      [ids, date, source.trim(), destination.trim(), dir],
    );

    push("state");

    res.json({
      added: r.length,
      skipped: ids.length - r.length,
    });
  }),
);

app.put(
  "/api/journeys/:id",
  auth,
  admin,
  h(async (req, res) => {
    const { date, source, destination, status } = req.body;

    if (status === "active") {
      await q(
        `UPDATE journeys
         SET status='planned'
         WHERE status='active'
         AND poll_id=(
           SELECT poll_id FROM journeys WHERE id=$1
         )`,
        [req.params.id],
      );
    }

    await q(
      `UPDATE journeys
       SET
         date=COALESCE($2,date),
         source=COALESCE($3,source),
         destination=COALESCE($4,destination),
         status=COALESCE($5,status),
         current_record_id=CASE
           WHEN $5='active' AND status='planned'
           THEN NULL
           ELSE current_record_id
         END
       WHERE id=$1`,
      [req.params.id, date, source, destination, status],
    );

    push("state");

    res.json({ ok: 1 });
  }),
);

// ADMIN RESTARTS JOURNEY
// FIXED: journey ID is now correctly passed as a query parameter.
app.post(
  "/api/journeys/:id/restart",
  auth,
  admin,
  h(async (req, res) => {
    const r = await q(
      `UPDATE journeys
       SET
         status = 'planned',
         current_record_id = NULL,
         reached_at = NULL,
         started_at = NULL
       WHERE id = $1
       RETURNING id`,
      [req.params.id],
    );

    if (!r.length) {
      return res.status(404).json({
        error: "Journey not found",
      });
    }

    push("state");

    res.json({ ok: 1 });
  }),
);

// CREATE RETURN JOURNEY
app.post(
  "/api/journeys/:id/return",
  auth,
  admin,
  h(async (req, res) => {
    const [j] = await q("SELECT * FROM journeys WHERE id=$1", [req.params.id]);

    if (!j || j.status !== "completed") {
      return res.status(400).json({
        error: "Complete the journey first",
      });
    }

    await q(
      `INSERT INTO journeys(
         poll_id,date,source,destination,direction
       )
       VALUES($1,$2,$3,$4,$5)`,
      [
        j.poll_id,
        req.body.date || new Date(),
        j.destination,
        j.source,
        j.direction === "return" ? "onward" : "return",
      ],
    );

    push("state");

    res.json({ ok: 1 });
  }),
);

// DELETE JOURNEY
app.delete(
  "/api/journeys/:id",
  auth,
  admin,
  h(async (req, res) => {
    await q("DELETE FROM journeys WHERE id=$1", [req.params.id]);

    push("state");

    res.json({ ok: 1 });
  }),
);

// START JOURNEY
app.post(
  "/api/polls/:id/start",
  auth,
  h(async (req, res) => {
    const id = +req.params.id;

    if (req.user.role !== "admin" && req.user.pollId !== id) {
      return res.status(403).json({
        error: "You can only start your own bus",
      });
    }

    const c = await pool.connect();

    let out = [500, { error: "Failed" }];
    let note = null;
    let name = req.user.name;

    try {
      await c.query("BEGIN");

      await c.query("SELECT pg_advisory_xact_lock($1)", [id]);

      const {
        rows: [pl],
      } = await c.query(
        `SELECT
           name,
           active_onward,
           active_return,
           (
             SELECT count(*)::int
             FROM records
             WHERE poll_id=$1
           ) n
         FROM polls
         WHERE id=$1`,
        [id],
      );

      const {
        rows: [on],
      } = await c.query(
        `SELECT id,direction
         FROM journeys
         WHERE poll_id=$1 AND status='active'`,
        [id],
      );

      const {
        rows: [nx],
      } = await c.query(
        `SELECT direction
         FROM journeys
         WHERE poll_id=$1 AND status='planned'
         ORDER BY date,id
         LIMIT 1`,
        [id],
      );

      const jd = (on || nx)?.direction;

      const isOn = jd
        ? !!pl?.[actCol(jd)]
        : !!(pl?.active_onward || pl?.active_return);

      if (req.user.role !== "admin" && !isOn) {
        out = [
          403,
          {
            error: `This bus is deactivated for the ${dirOf(jd)} journey. Ask the admin to activate it.`,
          },
        ];
      } else if (!pl?.n) {
        out = [
          400,
          {
            error: "No spots added yet. Ask the admin to add spots.",
          },
        ];
      } else if (on) {
        out = [200, { ok: 1, same: true }];
      } else {
        const {
          rows: [j],
        } = await c.query(
          `UPDATE journeys
           SET
             status = 'active',
             current_record_id = NULL,
             started_at = NOW(),
             reached_at = NOW()
           WHERE id = (
             SELECT id
             FROM journeys
             WHERE poll_id = $1 AND status = 'planned'
             ORDER BY date, id
             LIMIT 1
           )
           RETURNING source, destination, direction`,
          [id],
        );

        if (!j) {
          out = [
            400,
            {
              error: "No journey scheduled. Ask the admin to add a date.",
            },
          ];
        } else {
          name = pl.name;

          note = `Journey started: ${j.source} to ${j.destination}`;

          await c.query(
            `INSERT INTO messages(sender,sender_key,body)
             VALUES($1,$2,$3)`,
            [name, "p" + id, note],
          );

          out = [200, { ok: 1 }];
        }
      }

      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK").catch(() => 0);
      throw e;
    } finally {
      c.release();
    }

    if (note) {
      push("state");

      push("msg", {
        sender: name,
        body: note,
        reached: true,
      });
    }

    res.status(out[0]).json(out[1]);
  }),
);

// COMPLETE JOURNEY
app.post(
  "/api/polls/:id/end",
  auth,
  h(async (req, res) => {
    const id = +req.params.id;

    if (req.user.role !== "admin" && req.user.pollId !== id) {
      return res.status(403).json({
        error: "You can only complete your own bus",
      });
    }

    const [j] = await q(
      `SELECT
         j.id,
         j.source,
         j.destination,
         j.direction,
         j.current_record_id,
         p.name
       FROM journeys j
       JOIN polls p ON p.id=j.poll_id
       WHERE j.poll_id=$1 AND j.status='active'
       LIMIT 1`,
      [id],
    );

    if (!j) {
      return res.json({ ok: 1, same: true });
    }

    if (
      req.user.role !== "admin" &&
      !(
        await q(`SELECT 1 FROM polls WHERE id=$1 AND ${actCol(j.direction)}`, [
          id,
        ])
      ).length
    ) {
      return res.status(403).json({
        error: `This bus is deactivated for the ${dirOf(j.direction)} journey.`,
      });
    }

    const rs = await spotsFor(pool, id, j.direction);

    if (!rs.length || rs[rs.length - 1].id !== j.current_record_id) {
      return res.status(400).json({
        error:
          "Tick every spot, up to the last one, before completing the journey",
      });
    }

    if (
      !(
        await q(
          `UPDATE journeys
           SET status='completed',reached_at=now()
           WHERE id=$1 AND status='active'
           RETURNING id`,
          [j.id],
        )
      ).length
    ) {
      return res.json({ ok: 1, same: true });
    }

    const note = `Journey completed: ${j.source} to ${j.destination}`;

    await q(
      `INSERT INTO messages(sender,sender_key,body)
       VALUES($1,$2,$3)`,
      [j.name, "p" + id, note],
    );

    push("state");

    push("msg", {
      sender: j.name,
      body: note,
      reached: true,
    });

    res.json({ ok: 1 });
  }),
);

// UPDATE SPOT POSITION
app.post(
  "/api/polls/:id/position",
  auth,
  h(async (req, res) => {
    const id = +req.params.id;

    if (req.user.role !== "admin" && req.user.pollId !== id) {
      return res.status(403).json({
        error: "You can only change your own bus",
      });
    }

    const c = await pool.connect();

    let out = [500, { error: "Failed" }];

    const notes = [];

    try {
      await c.query("BEGIN");

      const {
        rows: [j],
      } = await c.query(
        `SELECT *
         FROM journeys
         WHERE poll_id=$1 AND status='active'
         ORDER BY id
         LIMIT 1
         FOR UPDATE`,
        [id],
      );

      if (!j) {
        out = [
          400,
          {
            error: "No active journey. Start the journey first.",
          },
        ];
      } else if (
        req.user.role !== "admin" &&
        !(
          await c.query(
            `SELECT 1 FROM polls WHERE id=$1 AND ${actCol(j.direction)}`,
            [id],
          )
        ).rows.length
      ) {
        out = [
          403,
          {
            error: `This bus is deactivated for the ${dirOf(j.direction)} journey.`,
          },
        ];
      } else {
        const rs = await spotsFor(c, id, j.direction);

        const cur = rs.findIndex((r) => r.id === j.current_record_id);

        const now = cur >= 0 ? rs[cur].label : "the start";

        let to;
        const status = "active";

        if (req.body.undo) {
          if (cur < 0 || req.body.from !== j.current_record_id) {
            out = [
              409,
              {
                error: `Already changed by someone on your bus. Now at ${now}`,
              },
            ];
          } else {
            to = cur > 0 ? rs[cur - 1].id : null;

            notes.push(`Correction: not yet at ${rs[cur].label}`);
          }
        } else {
          const i = rs.findIndex((r) => r.id === req.body.record_id);

          if (i < 0) {
            out = [400, { error: "Unknown spot" }];
          } else if (i <= cur) {
            out = [200, { ok: 1, same: true }];
          } else if (i > cur + 1) {
            out = [
              409,
              {
                error: `Someone on your bus marked a spot first. Now at ${now}`,
              },
            ];
          } else {
            to = rs[i].id;

            notes.push("Reached: " + rs[i].label);
          }
        }

        if (to !== undefined) {
          // IMPORTANT:
          // reached_at updates for every spot.
          // started_at remains unchanged.
          await c.query(
            `UPDATE journeys
             SET
               current_record_id=$2,
               reached_at=now(),
               status=$3
             WHERE id=$1`,
            [j.id, to, status],
          );

          for (const n of notes) {
            await c.query(
              `INSERT INTO messages(sender,sender_key,body)
               VALUES($1,$2,$3)`,
              [req.user.name, req.user.key, n],
            );
          }

          out = [200, { ok: 1 }];
        }
      }

      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK").catch(() => 0);
      throw e;
    } finally {
      c.release();
    }

    if (notes.length && out[0] === 200) {
      push("state");

      push("msg", {
        sender: req.user.name,
        body: notes[notes.length - 1],
        reached: true,
      });
    }

    res.status(out[0]).json(out[1]);
  }),
);

// MESSAGES
app.get(
  "/api/messages",
  auth,
  h(async (req, res) =>
    res.json(
      await q(
        `SELECT *
         FROM (
           SELECT *
           FROM messages
           ORDER BY id DESC
           LIMIT 100
         ) m
         ORDER BY id`,
      ),
    ),
  ),
);

app.post(
  "/api/messages",
  auth,
  h(async (req, res) => {
    const body = String(req.body.body || "")
      .trim()
      .slice(0, 1000);

    if (!body) {
      return res.status(400).json({
        error: "Empty message",
      });
    }

    await q(
      `INSERT INTO messages(sender,sender_key,body)
       VALUES($1,$2,$3)`,
      [req.user.name, req.user.key, body],
    );

    push("msg", {
      sender: req.user.name,
      body,
    });

    res.json({ ok: 1 });
  }),
);

app.put(
  "/api/messages/:id",
  auth,
  h(async (req, res) => {
    await q(
      `UPDATE messages
       SET body=$3,edited=true
       WHERE id=$1 AND sender_key=$2`,
      [req.params.id, req.user.key, String(req.body.body).slice(0, 1000)],
    );

    push("msg");

    res.json({ ok: 1 });
  }),
);

app.delete(
  "/api/messages",
  auth,
  admin,
  h(async (req, res) => {
    await q("DELETE FROM messages");

    push("msg");

    res.json({ ok: 1 });
  }),
);

app.delete(
  "/api/messages/:id",
  auth,
  h(async (req, res) => {
    if (req.user.role === "admin") {
      await q("DELETE FROM messages WHERE id=$1", [req.params.id]);
    } else {
      await q("DELETE FROM messages WHERE id=$1 AND sender_key=$2", [
        req.params.id,
        req.user.key,
      ]);
    }

    push("msg");

    res.json({ ok: 1 });
  }),
);

// FRONTEND STATIC FILES
const dist = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../frontend/dist/browser",
);

if (fs.existsSync(dist)) {
  app.use(
    express.static(dist, {
      maxAge: "1h",
    }),
  );

  app.get(/^\/(?!api).*/, (_, res) =>
    res.sendFile(path.join(dist, "index.html")),
  );
}

// HEALTH CHECK
app.get("/", (_, res) => res.send("Bus Tracker API is running"));

// SERVER START
if (!SERVERLESS) {
  server.listen(PORT, () => console.log("Poll running on :" + PORT));
}

export default app;
