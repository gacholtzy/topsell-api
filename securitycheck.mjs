// Tes pengaman: server dijalankan TANPA DEV_MODE (seperti di Vercel/hosting) dan dicek bahwa
// fitur tes mati, OTP tidak bocor, tebakan OTP dibatasi (di database), /docs dilindungi password,
// dan server menolak start dengan OTP lemah.
// Jalankan: node securitycheck.mjs   (butuh DATABASE_URL di .env, data tes dihapus lagi di akhir)
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import pg from "pg";

const ENV_FILE = new URL("./.env", import.meta.url);
if (fs.existsSync(ENV_FILE)) process.loadEnvFile(ENV_FILE);

const SERVER = new URL("./server.mjs", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const OTP = "4821";
const DOCS_USER = "topsell";
const DOCS_PASSWORD = "rahasia-tes";
const basic = (user, pass) => "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
// DEV_MODE harus "false" (bukan kosong): di Windows variabel kosong dianggap tidak ada, lalu .env mengisinya "true".
const safeEnv = (port, extra = {}) => ({ ...process.env, DEV_MODE: "false", PORT: String(port), OTP_CODE: OTP, ...extra });

// 1) Menolak start dengan OTP lemah / tanpa OTP_CODE
for (const otp of ["", "1234", "0000", "12"]) {
  const r = spawnSync(process.execPath, [SERVER], { env: safeEnv(8099, { OTP_CODE: otp }), encoding: "utf8", timeout: 20000 });
  assert.notEqual(r.status, 0, `harus menolak start dengan OTP_CODE="${otp}"`);
  assert.match(r.stderr, /OTP_CODE/, "pesan error menyebut OTP_CODE");
}

/** Jalankan server mode aman di port tertentu; kembalikan { stop, get, post }. */
async function startServer(port, extra) {
  const child = spawn(process.execPath, [SERVER], { env: safeEnv(port, extra), stdio: ["ignore", "pipe", "inherit"] });
  let log = "";
  child.stdout.on("data", (d) => (log += d));
  for (let i = 0; i < 80 && !log.includes("Mode aman"); i++) await new Promise((r) => setTimeout(r, 250));
  assert.ok(log.includes("Mode aman"), "server mode aman harus jalan, log: " + log);
  const base = `http://localhost:${port}`;
  return {
    log: () => log,
    stop: () => child.kill(),
    get: (path, headers = {}) => fetch(base + path, { headers }),
    post: async (path, body) => {
      const res = await fetch(base + "/api/v1" + path, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      return { http: res.status, ...(await res.json().catch(() => ({}))) };
    },
  };
}

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
const stamp = String(Date.now()).slice(-8);
const phones = [`6289911${stamp}`, `6289922${stamp}`]; // satu untuk login, satu untuk uji batas
const servers = [];

try {
  // 2) Server dengan DOCS_PASSWORD
  const s = await startServer(8099, { DOCS_PASSWORD, DOCS_USER });
  servers.push(s);
  assert.ok(!s.log().includes(OTP), "OTP tidak boleh tercetak di log");

  // /dev/* tidak ada (404), bukan 200/400/401 (yang berarti routenya hidup)
  assert.equal((await s.post("/dev/orders/INV-X/status", { status: "proses" })).http, 404, "/dev/* harus mati");

  // docs: butuh user + password
  for (const path of ["/docs", "/docs/openapi.yaml", "/openapi.yaml"]) {
    assert.equal((await s.get(path)).status, 401, `${path} tanpa login`);
    assert.equal((await s.get(path, { Authorization: basic(DOCS_USER, "salah") })).status, 401, `${path} password salah`);
    assert.equal((await s.get(path, { Authorization: basic("bukan-user", DOCS_PASSWORD) })).status, 401, `${path} user salah`);
    assert.equal((await s.get(path, { Authorization: basic(DOCS_USER, DOCS_PASSWORD) })).status, 200, `${path} login benar`);
  }

  // OTP tidak bocor di respons; 1234 tidak lagi berlaku
  const reg = await s.post("/users/register", { fullName: "Tes Aman", phoneNumber: phones[0] });
  assert.equal(reg.http, 200);
  assert.equal(reg.message, "OTP terkirim", "respons tidak boleh memuat kode OTP");
  const login = await s.post("/users/login", { phoneNumber: phones[0] });
  assert.ok(!JSON.stringify(login).includes(OTP) && !JSON.stringify(login).includes("1234"));
  assert.equal((await s.post("/users/verify-otp", { phoneNumber: phones[0], otp: "1234" })).http, 400);
  const ok = await s.post("/users/verify-otp", { phoneNumber: phones[0], otp: OTP });
  assert.equal(ok.http, 200, "OTP_CODE yang benar harus bisa login");
  assert.ok(ok.data.token);

  // tebakan OTP dibatasi: 5x salah -> 429, bahkan dengan kode yang benar
  assert.equal((await s.post("/users/register", { fullName: "Tes Batas", phoneNumber: phones[1] })).http, 200);
  for (let i = 0; i < 5; i++) {
    assert.equal((await s.post("/users/verify-otp", { phoneNumber: phones[1], otp: "0001" })).http, 400);
  }
  assert.equal((await s.post("/users/verify-otp", { phoneNumber: phones[1], otp: OTP })).http, 429, "setelah 5x salah, diblokir");

  // batas tersimpan di database (bukan memori): server baru melihat hitungan yang sama
  s.stop();
  const s2 = await startServer(8098, { DOCS_PASSWORD });
  servers.push(s2);
  assert.equal((await s2.post("/users/verify-otp", { phoneNumber: phones[1], otp: OTP })).http, 429, "tetap diblokir setelah server restart");

  // 3) Tanpa DOCS_PASSWORD, /docs mati (404). Dilewati bila .env lokal mengisi DOCS_PASSWORD (server memuat .env sendiri).
  if (process.env.DOCS_PASSWORD) {
    console.log("(lewati cek docs tanpa password: .env mengisi DOCS_PASSWORD)");
  } else {
    s2.stop();
    const s3 = await startServer(8097, {});
    servers.push(s3);
    assert.equal((await s3.get("/docs")).status, 404, "tanpa DOCS_PASSWORD /docs mati");
    assert.equal((await s3.get("/openapi.yaml")).status, 404);
  }

  console.log("securitycheck OK");
} finally {
  servers.forEach((x) => x.stop());
  await pool.query(`delete from users where phone_number = any($1)`, [phones]);
  await pool.query(`delete from otp_attempts where key = any($1) or key in ('ip:::1', 'ip:127.0.0.1', 'ip:::ffff:127.0.0.1')`,
    [phones.map((p) => `phone:${p}`)]);
  await pool.end();
}
