# Topsell API tiruan — catatan proyek untuk agen/sesi baru

API Node murni (`node:http`, satu berkas `server.mjs` ±1200 baris, dependensi hanya `pg`) yang meniru backend Topsell untuk frontend `D:\Topsell\topsell-checkout`.
Repo GitHub: `gacholtzy/topsell-api`. Hosting: Vercel (`https://topsellbelanjaapi.vercel.app`, handler `export default` menunggu `dbReady`).
Ini API **tiruan** untuk pengembangan/demo, bukan backend produksi (`api.topsellbelanja.com`, Go). Jangan simpan data pelanggan nyata di sini.

## Aturan kerja

- **Jangan commit/push kecuali diminta eksplisit.** Jawab dalam bahasa Indonesia, ringkas.
- Jangan mengulang/menyimpan kredensial yang pernah ditempel di chat; anggap bocor.
- Setelah mengubah `server.mjs`: jalankan `npm run check` (selfcheck + securitycheck) — keduanya harus "OK". Tambahkan kasus regresi di `selfcheck.mjs` untuk perilaku baru.
- Ubah `openapi.yaml` bila endpoint berubah (dokumentasi Scalar di `/docs`).

## Menjalankan

```bash
npm install
npm start            # port 8080; baca .env (DATABASE_URL, BITESHIP_API_KEY, DEV_MODE, WOO_*)
npm run check
```
Salin `.env.example` → `.env`. Tabel Postgres dibuat otomatis saat start. `DEV_MODE=true` hanya untuk laptop sendiri (OTP 1234, endpoint `/dev/*`, `/docs` terbuka).
Di hosting: `DEV_MODE` mati; `OTP_CODE` wajib (server menolak start bila kosong/1234/0000); `DOCS_PASSWORD` kosong = `/docs` mati (404).

## Sumber data

- **Produk:** WooCommerce (`WOO_URL`). Tanpa key → Store API publik (hanya produk katalog; di sebagian situs rute ini 500). Dengan `WOO_CONSUMER_KEY/SECRET` (izin Read) → REST v3 (produk tersembunyi ikut terbaca, hanya status `publish`). ID produk dari plugin Direct Checkout harus ada di situs `WOO_URL` (produk dev ada di `dev.topsellbelanja.com`).
- **Alamat/ongkir/tracking:** Biteship (`BITESHIP_API_KEY` sandbox cukup): `maps/areas`, `rates/couriers`, `orders`, `trackings`. Tanpa key → data contoh.
- **User, sesi, keranjang, order, poin, voucher:** Postgres (Neon).
- Tidak ada payment gateway: checkout hanya membuat order lokal; transfer manual/QRIS hanya tampilan.

## Pengaman yang sudah ada (jangan dilepas)

- Validasi masukan di satu titik bersama: `idOf` (ID 1–12 digit), `intOf` (qty bulat 1–1000), dipakai oleh `loadProduct`, `linesFromBody`, `/carts/items`, `/shippings/*` (maks 50 item). Mencegah qty negatif (F-01) dan path injection ke WooCommerce (F-03).
- Invoice `INV-LOCAL-<16 hex acak>` (F-02). `/orders` dan `/orders/qr-code` masih tanpa login karena frontend memanggil tanpa token; invoice lama format waktu masih bisa ditebak.
- Pembatas OTP di tabel `otp_attempts` (5 salah/nomor, 20 salah/IP per 15 menit, bertahan setelah restart). IP dibaca dari `x-forwarded-for` bila `TRUST_PROXY`/Vercel.
- `/docs` dan `openapi.yaml` dilindungi Basic Auth; Vercel memakai `outputDirectory: public` agar berkas root (server.mjs dll.) tidak disajikan statis.

## Masih terbuka (lihat `D:\Topsell\security-audit\run-1`)

F-04: satu `OTP_CODE` bersama untuk semua akun di mode hosting (desain; perlu OTP per-pengguna via WhatsApp sebelum dipakai nyata). Respons login/register/verify membedakan nomor terdaftar (enumerasi). NV-2: `/address/search`, `/shippings/*` publik memanggil Biteship tanpa throttle.

## Status (per 2026-11-17)

Commit terakhir `16f1fd3` (perbaikan F-01..F-03). Frontend-nya: `D:\Topsell\topsell-checkout` (baca `AGENTS.md` di sana untuk alur dan desain).
