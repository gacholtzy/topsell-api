import crypto from "node:crypto";

const ADMIN_SECRET = process.env.ADMIN_TOKEN_SECRET || crypto.randomBytes(32).toString("hex");
const ADMIN_TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 jam

function getAdminPassword(devMode) {
  return process.env.ADMIN_PASSWORD || (devMode ? "admin123" : "");
}

function signAdminToken() {
  const exp = Date.now() + ADMIN_TOKEN_TTL_MS;
  const payload = Buffer.from(JSON.stringify({ role: "admin", exp })).toString("base64url");
  const sig = crypto.createHmac("sha256", ADMIN_SECRET).update(payload).digest("base64url");
  return { token: `${payload}.${sig}`, expiresAt: new Date(exp).toISOString() };
}

function verifyAdminToken(req) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token || !token.includes(".")) return false;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return false;
  const expected = crypto.createHmac("sha256", ADMIN_SECRET).update(payload).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return data.role === "admin" && typeof data.exp === "number" && data.exp > Date.now();
  } catch {
    return false;
  }
}

export async function ensureAdminSchema(pool) {
  await pool.query(`
    create table if not exists admin_vouchers (
      id text primary key,
      name text not null,
      type text not null default 'fixed', -- fixed | percent | shipping
      description text not null default '',
      min_transaction integer not null default 0,
      discount integer not null default 0,
      max_discount integer not null default 0,
      fulfillment_type text not null default 'all', -- all | delivery | pickup
      qty integer not null default 100,
      used_qty integer not null default 0,
      is_auto_apply boolean not null default false,
      is_active boolean not null default true,
      start_date timestamptz not null default '2026-01-01T00:00:00+07:00',
      end_date timestamptz not null default '2026-12-31T23:59:59+07:00',
      created_at timestamptz not null default now()
    );

    create table if not exists admin_point_catalog (
      id text primary key,
      name text not null,
      point_cost integer not null,
      discount_value integer not null,
      min_transaction integer not null default 0,
      validity_days integer not null default 30,
      is_active boolean not null default true,
      created_at timestamptz not null default now()
    );

    create table if not exists admin_stores (
      id text primary key,
      name text not null,
      address text not null,
      area_name text not null,
      is_active boolean not null default true,
      created_at timestamptz not null default now()
    );

    create table if not exists admin_postal_codes (
      id text primary key,
      prefix_or_code text not null unique,
      city text not null default '',
      province text not null default 'Jawa Timur',
      is_active boolean not null default true,
      created_at timestamptz not null default now()
    );

    create table if not exists admin_payment_methods (
      id text primary key,
      group_key text not null,
      group_name text not null,
      key text not null,
      name text not null,
      admin_fee numeric not null default 0,
      admin_fee_type text not null default 'fixed', -- fixed | percentage
      is_active boolean not null default true,
      sort_order integer not null default 0,
      created_at timestamptz not null default now()
    );

    create table if not exists admin_webhooks (
      id text primary key,
      name text not null,
      url text not null,
      events text[] not null default '{order.created,order.status_updated}',
      secret text not null default '',
      is_active boolean not null default true,
      last_triggered_at timestamptz,
      created_at timestamptz not null default now()
    );

    create table if not exists admin_settings (
      key text primary key,
      value jsonb not null,
      updated_at timestamptz not null default now()
    );
  `);

  // Seed default data only when each table is empty
  const { rows: vc } = await pool.query(`select count(*)::int as c from admin_vouchers`);
  if (vc[0].c === 0) {
    await pool.query(`
      insert into admin_vouchers (id, name, type, description, min_transaction, discount, max_discount, fulfillment_type, is_auto_apply) values
        ('v-hemat10', 'HEMAT10', 'percent', 'Diskon 10% maks. Rp50.000', 100000, 10, 50000, 'all', false),
        ('v-potong100', 'POTONG100', 'fixed', 'Potongan Rp100.000 min. belanja Rp3.000.000', 3000000, 100000, 0, 'all', false),
        ('v-pickup25', 'PICKUP25', 'fixed', 'Potongan Rp25.000 khusus Ambil di Toko', 0, 25000, 0, 'pickup', false),
        ('v-ongkir', 'GRATISONGKIR', 'shipping', 'Gratis ongkir s/d Rp20.000', 0, 20000, 0, 'delivery', true)
      on conflict (id) do nothing
    `);
  }

  const { rows: pc } = await pool.query(`select count(*)::int as c from admin_point_catalog`);
  if (pc[0].c === 0) {
    await pool.query(`
      insert into admin_point_catalog (id, name, point_cost, discount_value, min_transaction, validity_days) values
        ('cat-10k', 'Voucher Rp10.000', 10000, 10000, 100000, 30),
        ('cat-25k', 'Voucher Rp25.000', 25000, 25000, 500000, 30)
      on conflict (id) do nothing
    `);
  }

  const { rows: sc } = await pool.query(`select count(*)::int as c from admin_stores`);
  if (sc[0].c === 0) {
    await pool.query(`
      insert into admin_stores (id, name, address, area_name) values
        ('store-sda', 'Topsell Sidoarjo', 'Jl. Ahmad Yani No. 1, Sidoarjo', 'Sidoarjo'),
        ('store-mlg', 'Topsell Malang', 'Jl. Ijen No. 10, Malang', 'Malang'),
        ('store-gsk', 'Topsell Gresik', 'Jl. Veteran No. 5, Gresik', 'Gresik')
      on conflict (id) do nothing
    `);
  }

  const { rows: zc } = await pool.query(`select count(*)::int as c from admin_postal_codes`);
  if (zc[0].c === 0) {
    await pool.query(`
      insert into admin_postal_codes (id, prefix_or_code, city, province) values
        ('pc-611', '611', 'Gresik', 'Jawa Timur'),
        ('pc-612', '612', 'Sidoarjo', 'Jawa Timur'),
        ('pc-613', '613', 'Mojokerto', 'Jawa Timur'),
        ('pc-614', '614', 'Jombang', 'Jawa Timur'),
        ('pc-641', '641', 'Kediri', 'Jawa Timur'),
        ('pc-651', '651', 'Malang', 'Jawa Timur'),
        ('pc-662', '662', 'Tulungagung', 'Jawa Timur')
      on conflict (id) do nothing
    `);
  }

  const { rows: pmc } = await pool.query(`select count(*)::int as c from admin_payment_methods`);
  if (pmc[0].c === 0) {
    await pool.query(`
      insert into admin_payment_methods (id, group_key, group_name, key, name, admin_fee, admin_fee_type, sort_order) values
        ('pm-manual', 'bank', 'Transfer Bank', 'manual', 'Transfer Manual', 0, 'fixed', 1),
        ('pm-bca', 'va', 'Virtual Account', 'bca', 'BCA Virtual Account', 4000, 'fixed', 2),
        ('pm-bni', 'va', 'Virtual Account', 'bni', 'BNI Virtual Account', 4000, 'fixed', 3),
        ('pm-qris', 'qris', 'QRIS', 'qris', 'QRIS', 0.7, 'percentage', 4),
        ('pm-cc', 'store', 'Bayar di Toko', 'cc', 'Tunai / Debit / Kartu Kredit di Toko', 0, 'fixed', 5)
      on conflict (id) do nothing
    `);
  }

  const { rows: stc } = await pool.query(`select count(*)::int as c from admin_settings`);
  if (stc[0].c === 0) {
    await pool.query(
      `insert into admin_settings (key, value) values ($1, $2::jsonb), ($3, $4::jsonb) on conflict (key) do nothing`,
      [
        "app_settings",
        JSON.stringify({
          store_name: "Topsell Belanja",
          support_whatsapp: "628113000000",
          point_to_rupiah: 1,
          new_member_points: 20000,
          banner_imager: [],
          meta_your_pixel: "",
          body_script: "",
        }),
        "store_areas",
        JSON.stringify([
          { id: "area-sda", name: "Sidoarjo", city: "Sidoarjo", province: "Jawa Timur", active: true },
          { id: "area-mlg", name: "Malang", city: "Malang", province: "Jawa Timur", active: true },
          { id: "area-gsk", name: "Gresik", city: "Gresik", province: "Jawa Timur", active: true },
          { id: "area-mjk", name: "Mojokerto", city: "Mojokerto", province: "Jawa Timur", active: true },
        ]),
      ]
    );
  }
}

// ---------------------------------------------------------------- Live data helpers for checkout
export async function getActiveStores(q, search = "") {
  const rows = await q(
    `select id, name, address, area_name as "areaName" from admin_stores
     where is_active = true and (lower(name) like $1 or lower(address) like $1 or lower(area_name) like $1)
     order by created_at asc`,
    [`%${String(search || "").toLowerCase()}%`]
  );
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    address: r.address,
    storeArea: { name: r.areaName, cityIds: [] },
  }));
}

export async function getActivePaymentGroups(q) {
  const rows = await q(
    `select id, group_key as "groupKey", group_name as "groupName", key, name,
            admin_fee::float8 as "adminFee", admin_fee_type as "adminFeeType"
     from admin_payment_methods
     where is_active = true
     order by sort_order asc, created_at asc`
  );
  const groups = new Map();
  for (const r of rows) {
    if (!groups.has(r.groupKey)) {
      groups.set(r.groupKey, { name: r.groupName, key: r.groupKey, paymentMethods: [] });
    }
    const g = groups.get(r.groupKey);
    g.paymentMethods.push({
      id: r.id,
      key: r.key,
      name: r.name,
      description: r.name,
      excerpt: r.name,
      icon: "/images/placeholder-image.svg",
      adminFee: r.adminFee,
      adminFeeType: r.adminFeeType,
      paymentGroup: { name: r.groupName, key: r.groupKey },
    });
  }
  return [...groups.values()];
}

export async function getActiveVouchers(q) {
  const rows = await q(
    `select id, name, type, description, min_transaction as "minTransaction", discount,
            max_discount as "maxDiscount", fulfillment_type as "fulfillmentType",
            qty, used_qty as "usedQty", is_auto_apply as "isAutoApply",
            start_date as "startDate", end_date as "endDate"
     from admin_vouchers
     where is_active = true and used_qty < qty and end_date > now()
     order by created_at desc`
  );
  return rows.map((v) => ({
    ...v,
    productIDs: [],
    paymentMethodIDs: [],
    variationIDs: [],
    isCancellable: true,
  }));
}

export async function getActivePointCatalog(q) {
  return q(
    `select id, name, point_cost as "pointCost", discount_value as "discountValue",
            min_transaction as "minTransaction", validity_days as "validityDays",
            case when is_active then 'active' else 'inactive' end as status
     from admin_point_catalog
     where is_active = true
     order by point_cost asc`
  );
}

export async function isTopsellPostalDb(q, postal) {
  const p = String(postal || "").trim();
  if (!p) return false;
  const rows = await q(`select prefix_or_code from admin_postal_codes where is_active = true`);
  return rows.some((r) => p.startsWith(r.prefix_or_code));
}

export async function getAppSettingsMap(q) {
  const rows = await q(`select key, value from admin_settings`);
  const map = Object.fromEntries(rows.map((r) => [r.key, r.value]));
  return map;
}

export async function triggerWebhooks(q, event, payload) {
  try {
    const hooks = await q(
      `select id, url, secret from admin_webhooks where is_active = true and $1 = any(events)`,
      [event]
    );
    if (!hooks.length) return;
    const body = JSON.stringify({ event, timestamp: new Date().toISOString(), data: payload });
    await Promise.allSettled(
      hooks.map(async (h) => {
        const headers = { "Content-Type": "application/json", "X-Topsell-Event": event };
        if (h.secret) {
          headers["X-Topsell-Signature"] = crypto.createHmac("sha256", h.secret).update(body).digest("hex");
        }
        await fetch(h.url, { method: "POST", headers, body, signal: AbortSignal.timeout(5000) });
        await q(`update admin_webhooks set last_triggered_at = now() where id = $1`, [h.id]);
      })
    );
  } catch {
    // Webhook delivery must not break checkout or order updates
  }
}

// ---------------------------------------------------------------- Admin HTTP routes
export function buildAdminRoutes(ctx) {
  const { q, tx, ok, send, readBody, HttpError, DEV_MODE, ORDER_STATUS_SQL, POINTS_SQL, PICKUP_ID, BITESHIP_KEY, TRACKING_URL, bookShipment } = ctx;

  const requireAdmin = (req) => {
    const pass = getAdminPassword(DEV_MODE);
    if (!pass) throw new HttpError(401, "Admin belum dikonfigurasi");
    if (!verifyAdminToken(req)) throw new HttpError(401, "Sesi admin berakhir. Silakan masuk kembali.");
  };

  const slugId = (prefix, raw) =>
    `${prefix}-${String(raw || crypto.randomBytes(4).toString("hex")).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) || crypto.randomBytes(3).toString("hex")}-${crypto.randomBytes(2).toString("hex")}`;

  return [
    ["POST", /^\/admin\/login$/, async (req, res) => {
      const configured = getAdminPassword(DEV_MODE);
      if (!configured) throw new HttpError(503, "ADMIN_PASSWORD belum diatur di server");
      const { password } = await readBody(req);
      if (!password || String(password) !== configured) {
        throw new HttpError(401, "Password admin salah");
      }
      ok(res, signAdminToken(), "Login admin berhasil");
    }],

    ["GET", /^\/admin\/overview$/, async (req, res) => {
      requireAdmin(req);
      const [summary] = await q(`
        select
          count(*)::int as total_orders,
          coalesce(sum((data->>'total')::numeric) filter (where ${ORDER_STATUS_SQL} in ('proses','sent','complete')), 0)::bigint as total_revenue,
          count(*) filter (where ${ORDER_STATUS_SQL} = 'pending')::int as pending_orders,
          count(*) filter (where ${ORDER_STATUS_SQL} in ('proses','sent'))::int as active_orders,
          count(*) filter (where ${ORDER_STATUS_SQL} = 'complete')::int as completed_orders,
          count(*) filter (where ${ORDER_STATUS_SQL} = 'expired')::int as expired_orders
        from orders
      `);
      const [userStats] = await q(`
        select
          (select count(*)::int from users) as total_users,
          (select coalesce(sum(amount), 0)::bigint from point_ledger) as total_points
      `);
      const daily = await q(`
        with days as (
          select generate_series(current_date - interval '6 days', current_date, interval '1 day')::date as day
        )
        select
          to_char(d.day, 'DD Mon') as label,
          count(o.id)::int as orders,
          coalesce(sum((o.data->>'total')::numeric) filter (where o.data->>'status' in ('proses','sent','complete')), 0)::bigint as revenue
        from days d
        left join orders o on o.created_at::date = d.day
        group by d.day
        order by d.day asc
      `);
      const recent = await q(`
        select invoice, data, ${ORDER_STATUS_SQL} as status, created_at as "createdAt"
        from orders order by created_at desc limit 6
      `);
      ok(res, {
        metrics: {
          totalOrders: summary.total_orders,
          totalRevenue: Number(summary.total_revenue),
          pendingOrders: summary.pending_orders,
          activeOrders: summary.active_orders,
          completedOrders: summary.completed_orders,
          expiredOrders: summary.expired_orders,
          totalUsers: userStats.total_users,
          totalPoints: Number(userStats.total_points),
        },
        chart: daily.map((r) => ({ label: r.label, orders: r.orders, revenue: Number(r.revenue) })),
        recentOrders: recent.map((r) => ({ ...r.data, status: r.status, createdAt: r.createdAt })),
      });
    }],

    // --- Orders / Penjualan
    ["GET", /^\/admin\/orders$/, async (req, res, m, url) => {
      requireAdmin(req);
      const status = url.searchParams.get("status") || "";
      const search = (url.searchParams.get("search") || "").trim().toLowerCase();
      const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
      const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit")) || 15));

      const conds = [];
      const params = [];
      if (status && status !== "all") {
        params.push(status);
        conds.push(`(${ORDER_STATUS_SQL}) = $${params.length}`);
      }
      if (search) {
        params.push(`%${search}%`);
        conds.push(`(lower(invoice) like $${params.length} or lower(coalesce(data->>'name','')) like $${params.length} or lower(coalesce(data->>'phone','')) like $${params.length})`);
      }
      const where = conds.length ? `where ${conds.join(" and ")}` : "";
      params.push(limit, (page - 1) * limit);

      const rows = await q(
        `select data, ${ORDER_STATUS_SQL} as status, created_at as "createdAt", count(*) over ()::int as total
         from orders ${where}
         order by created_at desc
         limit $${params.length - 1} offset $${params.length}`,
        params
      );
      const total = rows[0]?.total ?? 0;
      ok(res, {
        orders: rows.map((r) => ({ ...r.data, status: r.status, createdAt: r.createdAt })),
        total,
        totalPage: Math.ceil(total / limit),
      });
    }],

    ["PATCH", /^\/admin\/orders\/([\w-]+)\/status$/, async (req, res, m) => {
      requireAdmin(req);
      const b = await readBody(req);
      const allowed = new Set(["pending", "proses", "sent", "complete", "expired"]);
      if (!allowed.has(b.status)) throw new HttpError(400, "Status tidak valid");
      const [cur] = await q(`select data from orders where invoice = $1`, [m[1]]);
      if (!cur) throw new HttpError(404, "Order tidak ditemukan");

      const patch = { status: b.status };
      const o = cur.data;
      const delivery = o.shipping?.id !== PICKUP_ID;
      const paidOrLater = ["proses", "sent", "complete"].includes(b.status);
      if (b.courierName) patch.courierName = b.courierName;
      if (b.trackingNumber) {
        patch.trackingNumber = b.trackingNumber;
        patch.trackingUrl = TRACKING_URL.replace("{resi}", encodeURIComponent(b.trackingNumber));
      } else if (delivery && paidOrLater && !o.biteshipTrackingID && !o.trackingNumber) {
        if (BITESHIP_KEY) {
          Object.assign(patch, await bookShipment(o));
        } else if (b.status !== "proses") {
          patch.courierName = b.courierName || "J&T Express";
          patch.trackingNumber = `JT${Date.now().toString().slice(-10)}`;
          patch.trackingUrl = TRACKING_URL.replace("{resi}", encodeURIComponent(patch.trackingNumber));
        }
      }
      await q(`update orders set data = data || $1::jsonb where invoice = $2`, [patch, m[1]]);
      triggerWebhooks(q, "order.status_updated", { invoice: m[1], ...patch });
      ok(res, { invoice: m[1], ...patch }, "Status pesanan diperbarui");
    }],

    // --- Vouchers
    ["GET", /^\/admin\/vouchers$/, async (req, res) => {
      requireAdmin(req);
      const rows = await q(`
        select id, name, type, description, min_transaction as "minTransaction", discount,
               max_discount as "maxDiscount", fulfillment_type as "fulfillmentType",
               qty, used_qty as "usedQty", is_auto_apply as "isAutoApply", is_active as "isActive",
               start_date as "startDate", end_date as "endDate"
        from admin_vouchers order by created_at desc
      `);
      ok(res, rows);
    }],
    ["POST", /^\/admin\/vouchers$/, async (req, res) => {
      requireAdmin(req);
      const b = await readBody(req);
      if (!b.name) throw new HttpError(400, "Kode voucher wajib diisi");
      const id = slugId("v", b.name);
      const [row] = await q(
        `insert into admin_vouchers (id, name, type, description, min_transaction, discount, max_discount, fulfillment_type, qty, is_auto_apply, is_active, end_date)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, coalesce($12::timestamptz, '2026-12-31T23:59:59+07:00'))
         returning id, name, type, description, min_transaction as "minTransaction", discount, max_discount as "maxDiscount",
                   fulfillment_type as "fulfillmentType", qty, used_qty as "usedQty", is_auto_apply as "isAutoApply", is_active as "isActive",
                   start_date as "startDate", end_date as "endDate"`,
        [
          id,
          String(b.name).trim().toUpperCase(),
          b.type || "fixed",
          b.description || "",
          Math.max(0, Number(b.minTransaction) || 0),
          Math.max(0, Number(b.discount) || 0),
          Math.max(0, Number(b.maxDiscount) || 0),
          b.fulfillmentType || "all",
          Math.max(1, Number(b.qty) || 100),
          Boolean(b.isAutoApply),
          b.isActive !== false,
          b.endDate || null,
        ]
      );
      ok(res, row, "Voucher dibuat");
    }],
    ["PUT", /^\/admin\/vouchers\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      const b = await readBody(req);
      const [row] = await q(
        `update admin_vouchers set
           name = coalesce($2, name),
           type = coalesce($3, type),
           description = coalesce($4, description),
           min_transaction = coalesce($5, min_transaction),
           discount = coalesce($6, discount),
           max_discount = coalesce($7, max_discount),
           fulfillment_type = coalesce($8, fulfillment_type),
           qty = coalesce($9, qty),
           is_auto_apply = coalesce($10, is_auto_apply),
           is_active = coalesce($11, is_active)
         where id = $1
         returning id, name, type, description, min_transaction as "minTransaction", discount, max_discount as "maxDiscount",
                   fulfillment_type as "fulfillmentType", qty, used_qty as "usedQty", is_auto_apply as "isAutoApply", is_active as "isActive"`,
        [
          m[1],
          b.name ? String(b.name).trim().toUpperCase() : null,
          b.type ?? null,
          b.description ?? null,
          b.minTransaction != null ? Number(b.minTransaction) : null,
          b.discount != null ? Number(b.discount) : null,
          b.maxDiscount != null ? Number(b.maxDiscount) : null,
          b.fulfillmentType ?? null,
          b.qty != null ? Number(b.qty) : null,
          b.isAutoApply != null ? Boolean(b.isAutoApply) : null,
          b.isActive != null ? Boolean(b.isActive) : null,
        ]
      );
      if (!row) throw new HttpError(404, "Voucher tidak ditemukan");
      ok(res, row, "Voucher diperbarui");
    }],
    ["DELETE", /^\/admin\/vouchers\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      await q(`delete from admin_vouchers where id = $1`, [m[1]]);
      ok(res, { id: m[1] }, "Voucher dihapus");
    }],

    // --- Points Catalog & Adjustment
    ["GET", /^\/admin\/points\/catalog$/, async (req, res) => {
      requireAdmin(req);
      const rows = await q(`
        select id, name, point_cost as "pointCost", discount_value as "discountValue",
               min_transaction as "minTransaction", validity_days as "validityDays", is_active as "isActive"
        from admin_point_catalog order by point_cost asc
      `);
      ok(res, rows);
    }],
    ["POST", /^\/admin\/points\/catalog$/, async (req, res) => {
      requireAdmin(req);
      const b = await readBody(req);
      if (!b.name) throw new HttpError(400, "Nama reward wajib diisi");
      const id = slugId("cat", b.name);
      const [row] = await q(
        `insert into admin_point_catalog (id, name, point_cost, discount_value, min_transaction, validity_days, is_active)
         values ($1, $2, $3, $4, $5, $6, $7)
         returning id, name, point_cost as "pointCost", discount_value as "discountValue",
                   min_transaction as "minTransaction", validity_days as "validityDays", is_active as "isActive"`,
        [
          id,
          String(b.name).trim(),
          Math.max(1, Number(b.pointCost) || 1000),
          Math.max(1, Number(b.discountValue) || 1000),
          Math.max(0, Number(b.minTransaction) || 0),
          Math.max(1, Number(b.validityDays) || 30),
          b.isActive !== false,
        ]
      );
      ok(res, row, "Katalog poin ditambahkan");
    }],
    ["PUT", /^\/admin\/points\/catalog\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      const b = await readBody(req);
      const [row] = await q(
        `update admin_point_catalog set
           name = coalesce($2, name),
           point_cost = coalesce($3, point_cost),
           discount_value = coalesce($4, discount_value),
           min_transaction = coalesce($5, min_transaction),
           validity_days = coalesce($6, validity_days),
           is_active = coalesce($7, is_active)
         where id = $1
         returning id, name, point_cost as "pointCost", discount_value as "discountValue",
                   min_transaction as "minTransaction", validity_days as "validityDays", is_active as "isActive"`,
        [
          m[1],
          b.name ?? null,
          b.pointCost != null ? Number(b.pointCost) : null,
          b.discountValue != null ? Number(b.discountValue) : null,
          b.minTransaction != null ? Number(b.minTransaction) : null,
          b.validityDays != null ? Number(b.validityDays) : null,
          b.isActive != null ? Boolean(b.isActive) : null,
        ]
      );
      if (!row) throw new HttpError(404, "Katalog tidak ditemukan");
      ok(res, row, "Katalog poin diperbarui");
    }],
    ["DELETE", /^\/admin\/points\/catalog\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      await q(`delete from admin_point_catalog where id = $1`, [m[1]]);
      ok(res, { id: m[1] }, "Katalog poin dihapus");
    }],
    ["POST", /^\/admin\/points\/adjust$/, async (req, res) => {
      requireAdmin(req);
      const b = await readBody(req);
      const amount = Math.trunc(Number(b.amount) || 0);
      if (!b.userId || !amount) throw new HttpError(400, "User dan jumlah poin wajib diisi");
      const entry = await tx(async (client) => {
        const { rows: u } = await client.query(`select id from users where id = $1 for update`, [b.userId]);
        if (!u.length) throw new HttpError(404, "User tidak ditemukan");
        const { rows: bal } = await client.query(
          `select coalesce(sum(amount), 0)::int as n from point_ledger where user_id = $1`,
          [b.userId]
        );
        const nextBalance = bal[0].n + amount;
        if (nextBalance < 0) throw new HttpError(400, "Saldo poin user tidak boleh minus");
        const { rows } = await client.query(
          `insert into point_ledger (user_id, type, amount, balance_after, description)
           values ($1, $2, $3, $4, $5) returning id, amount, balance_after as "balanceAfter", description, created_at as "createdAt"`,
          [b.userId, amount > 0 ? "earn" : "redeem", amount, nextBalance, b.description || "Penyesuaian admin"]
        );
        return rows[0];
      });
      ok(res, entry, "Saldo poin diperbarui");
    }],

    // --- Users
    ["GET", /^\/admin\/users$/, async (req, res, m, url) => {
      requireAdmin(req);
      const search = (url.searchParams.get("search") || "").trim().toLowerCase();
      const params = search ? [`%${search}%`] : [];
      const where = search
        ? `where lower(u.full_name) like $1 or lower(u.phone_number) like $1 or lower(u.email) like $1`
        : "";
      const rows = await q(
        `select u.id, u.full_name as "fullName", u.phone_number as "phoneNumber", u.email,
                u.email_valid as "isEmailValid", ${POINTS_SQL} as points, u.created_at as "createdAt",
                (select count(*)::int from orders o where o.user_id = u.id) as "orderCount",
                (select coalesce(sum((o.data->>'total')::numeric), 0)::bigint from orders o where o.user_id = u.id and o.data->>'status' in ('proses','sent','complete')) as "totalSpent"
         from users u ${where}
         order by u.created_at desc limit 100`,
        params
      );
      ok(res, rows.map((r) => ({ ...r, totalSpent: Number(r.totalSpent) })));
    }],

    // --- Postal Codes
    ["GET", /^\/admin\/postal-codes$/, async (req, res) => {
      requireAdmin(req);
      ok(res, await q(`select id, prefix_or_code as "prefixOrCode", city, province, is_active as "isActive" from admin_postal_codes order by prefix_or_code asc`));
    }],
    ["POST", /^\/admin\/postal-codes$/, async (req, res) => {
      requireAdmin(req);
      const b = await readBody(req);
      const code = String(b.prefixOrCode || "").trim();
      if (!/^\d{3,6}$/.test(code)) throw new HttpError(400, "Kode pos / prefix harus 3-6 digit angka");
      const [row] = await q(
        `insert into admin_postal_codes (id, prefix_or_code, city, province, is_active)
         values ($1, $2, $3, $4, $5)
         returning id, prefix_or_code as "prefixOrCode", city, province, is_active as "isActive"`,
        [`pc-${code}`, code, b.city || "", b.province || "Jawa Timur", b.isActive !== false]
      );
      ok(res, row, "Kode pos ditambahkan");
    }],
    ["PUT", /^\/admin\/postal-codes\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      const b = await readBody(req);
      const [row] = await q(
        `update admin_postal_codes set
           prefix_or_code = coalesce($2, prefix_or_code),
           city = coalesce($3, city),
           province = coalesce($4, province),
           is_active = coalesce($5, is_active)
         where id = $1
         returning id, prefix_or_code as "prefixOrCode", city, province, is_active as "isActive"`,
        [m[1], b.prefixOrCode ?? null, b.city ?? null, b.province ?? null, b.isActive != null ? Boolean(b.isActive) : null]
      );
      if (!row) throw new HttpError(404, "Kode pos tidak ditemukan");
      ok(res, row, "Kode pos diperbarui");
    }],
    ["DELETE", /^\/admin\/postal-codes\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      await q(`delete from admin_postal_codes where id = $1`, [m[1]]);
      ok(res, { id: m[1] }, "Kode pos dihapus");
    }],

    // --- Store Locations
    ["GET", /^\/admin\/stores$/, async (req, res) => {
      requireAdmin(req);
      ok(res, await q(`select id, name, address, area_name as "areaName", is_active as "isActive" from admin_stores order by created_at asc`));
    }],
    ["POST", /^\/admin\/stores$/, async (req, res) => {
      requireAdmin(req);
      const b = await readBody(req);
      if (!b.name || !b.address) throw new HttpError(400, "Nama dan alamat toko wajib diisi");
      const id = slugId("store", b.name);
      const [row] = await q(
        `insert into admin_stores (id, name, address, area_name, is_active)
         values ($1, $2, $3, $4, $5)
         returning id, name, address, area_name as "areaName", is_active as "isActive"`,
        [id, String(b.name).trim(), String(b.address).trim(), String(b.areaName || "Sidoarjo").trim(), b.isActive !== false]
      );
      ok(res, row, "Lokasi toko ditambahkan");
    }],
    ["PUT", /^\/admin\/stores\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      const b = await readBody(req);
      const [row] = await q(
        `update admin_stores set
           name = coalesce($2, name),
           address = coalesce($3, address),
           area_name = coalesce($4, area_name),
           is_active = coalesce($5, is_active)
         where id = $1
         returning id, name, address, area_name as "areaName", is_active as "isActive"`,
        [m[1], b.name ?? null, b.address ?? null, b.areaName ?? null, b.isActive != null ? Boolean(b.isActive) : null]
      );
      if (!row) throw new HttpError(404, "Toko tidak ditemukan");
      ok(res, row, "Lokasi toko diperbarui");
    }],
    ["DELETE", /^\/admin\/stores\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      await q(`delete from admin_stores where id = $1`, [m[1]]);
      ok(res, { id: m[1] }, "Lokasi toko dihapus");
    }],

    // --- Payment Methods
    ["GET", /^\/admin\/payment-methods$/, async (req, res) => {
      requireAdmin(req);
      ok(res, await q(`
        select id, group_key as "groupKey", group_name as "groupName", key, name,
               admin_fee::float8 as "adminFee", admin_fee_type as "adminFeeType",
               is_active as "isActive", sort_order as "sortOrder"
        from admin_payment_methods order by sort_order asc, created_at asc
      `));
    }],
    ["POST", /^\/admin\/payment-methods$/, async (req, res) => {
      requireAdmin(req);
      const b = await readBody(req);
      if (!b.name || !b.key) throw new HttpError(400, "Nama dan key metode pembayaran wajib diisi");
      const id = slugId("pm", b.key);
      const [row] = await q(
        `insert into admin_payment_methods (id, group_key, group_name, key, name, admin_fee, admin_fee_type, is_active, sort_order)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         returning id, group_key as "groupKey", group_name as "groupName", key, name,
                   admin_fee::float8 as "adminFee", admin_fee_type as "adminFeeType",
                   is_active as "isActive", sort_order as "sortOrder"`,
        [
          id,
          b.groupKey || "va",
          b.groupName || "Virtual Account",
          String(b.key).trim().toLowerCase(),
          String(b.name).trim(),
          Math.max(0, Number(b.adminFee) || 0),
          b.adminFeeType === "percentage" ? "percentage" : "fixed",
          b.isActive !== false,
          Number(b.sortOrder) || 10,
        ]
      );
      ok(res, row, "Metode pembayaran ditambahkan");
    }],
    ["PUT", /^\/admin\/payment-methods\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      const b = await readBody(req);
      const [row] = await q(
        `update admin_payment_methods set
           group_key = coalesce($2, group_key),
           group_name = coalesce($3, group_name),
           key = coalesce($4, key),
           name = coalesce($5, name),
           admin_fee = coalesce($6, admin_fee),
           admin_fee_type = coalesce($7, admin_fee_type),
           is_active = coalesce($8, is_active),
           sort_order = coalesce($9, sort_order)
         where id = $1
         returning id, group_key as "groupKey", group_name as "groupName", key, name,
                   admin_fee::float8 as "adminFee", admin_fee_type as "adminFeeType",
                   is_active as "isActive", sort_order as "sortOrder"`,
        [
          m[1],
          b.groupKey ?? null,
          b.groupName ?? null,
          b.key ?? null,
          b.name ?? null,
          b.adminFee != null ? Number(b.adminFee) : null,
          b.adminFeeType ?? null,
          b.isActive != null ? Boolean(b.isActive) : null,
          b.sortOrder != null ? Number(b.sortOrder) : null,
        ]
      );
      if (!row) throw new HttpError(404, "Metode pembayaran tidak ditemukan");
      ok(res, row, "Metode pembayaran diperbarui");
    }],
    ["DELETE", /^\/admin\/payment-methods\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      await q(`delete from admin_payment_methods where id = $1`, [m[1]]);
      ok(res, { id: m[1] }, "Metode pembayaran dihapus");
    }],

    // --- Settings (App Settings & Store Areas)
    ["GET", /^\/admin\/settings$/, async (req, res) => {
      requireAdmin(req);
      ok(res, await getAppSettingsMap(q));
    }],
    ["PUT", /^\/admin\/settings$/, async (req, res) => {
      requireAdmin(req);
      const b = await readBody(req);
      if (b.app_settings) {
        await q(
          `insert into admin_settings (key, value, updated_at) values ('app_settings', $1::jsonb, now())
           on conflict (key) do update set value = excluded.value, updated_at = now()`,
          [JSON.stringify(b.app_settings)]
        );
      }
      if (b.store_areas) {
        await q(
          `insert into admin_settings (key, value, updated_at) values ('store_areas', $1::jsonb, now())
           on conflict (key) do update set value = excluded.value, updated_at = now()`,
          [JSON.stringify(b.store_areas)]
        );
      }
      ok(res, await getAppSettingsMap(q), "Pengaturan disimpan");
    }],

    // --- Webhooks
    ["GET", /^\/admin\/webhooks$/, async (req, res) => {
      requireAdmin(req);
      ok(res, await q(`
        select id, name, url, events, secret, is_active as "isActive", last_triggered_at as "lastTriggeredAt"
        from admin_webhooks order by created_at desc
      `));
    }],
    ["POST", /^\/admin\/webhooks$/, async (req, res) => {
      requireAdmin(req);
      const b = await readBody(req);
      if (!b.name || !b.url) throw new HttpError(400, "Nama dan URL webhook wajib diisi");
      const id = slugId("wh", b.name);
      const events = Array.isArray(b.events) && b.events.length ? b.events : ["order.created", "order.status_updated"];
      const [row] = await q(
        `insert into admin_webhooks (id, name, url, events, secret, is_active)
         values ($1, $2, $3, $4::text[], $5, $6)
         returning id, name, url, events, secret, is_active as "isActive", last_triggered_at as "lastTriggeredAt"`,
        [id, String(b.name).trim(), String(b.url).trim(), events, b.secret || "", b.isActive !== false]
      );
      ok(res, row, "Webhook ditambahkan");
    }],
    ["PUT", /^\/admin\/webhooks\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      const b = await readBody(req);
      const [row] = await q(
        `update admin_webhooks set
           name = coalesce($2, name),
           url = coalesce($3, url),
           events = coalesce($4::text[], events),
           secret = coalesce($5, secret),
           is_active = coalesce($6, is_active)
         where id = $1
         returning id, name, url, events, secret, is_active as "isActive", last_triggered_at as "lastTriggeredAt"`,
        [m[1], b.name ?? null, b.url ?? null, Array.isArray(b.events) ? b.events : null, b.secret ?? null, b.isActive != null ? Boolean(b.isActive) : null]
      );
      if (!row) throw new HttpError(404, "Webhook tidak ditemukan");
      ok(res, row, "Webhook diperbarui");
    }],
    ["DELETE", /^\/admin\/webhooks\/([\w-]+)$/, async (req, res, m) => {
      requireAdmin(req);
      await q(`delete from admin_webhooks where id = $1`, [m[1]]);
      ok(res, { id: m[1] }, "Webhook dihapus");
    }],
  ];
}
