// ============================================================
// DonateGold Relay Server
// Menjembatani webhook Saweria / Sosiabuzz / Tako ke game Roblox.
// Roblox tidak bisa menerima webhook langsung, jadi game akan
// "polling" (fetch berkala) ke server ini lewat HttpService.
// ============================================================

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; } // simpan raw body, dipakai verifikasi signature Saweria
}));
app.use(express.static(path.join(__dirname, 'public'))); // halaman cek username ada di sini

const PORT = process.env.PORT || 3000;

// ==== GANTI / ISI VIA ENVIRONMENT VARIABLES DI HOSTING KAMU ====
const SHARED_KEY = process.env.SHARED_KEY || 'ganti-ini-kunci-webhook';        // dipakai di URL webhook platform donasi (?key=...)
const ROBLOX_KEY = process.env.ROBLOX_KEY || 'ganti-ini-kunci-roblox';        // dipakai game Roblox saat polling
const SAWERIA_STREAM_KEY = process.env.SAWERIA_STREAM_KEY || '';             // opsional, untuk verifikasi signature Saweria
const TAKO_API_KEY = process.env.TAKO_API_KEY || '';                         // API Key Tako (buat ambil detail nama/pesan donatur)
const TAKO_CALLBACK_SECRET = process.env.TAKO_CALLBACK_SECRET || '';         // opsional, untuk verifikasi X-Tako-Signature
const ADMIN_KEY = process.env.ADMIN_KEY || 'ganti-ini-kunci-admin';          // dipakai khusus untuk reset/kosongkan data

const admin = require('firebase-admin');

// Mengambil kunci dari Environment Variables Render
const FIREBASE_DB_URL = process.env.FIREBASE_DB_URL || '';
const FIREBASE_CREDENTIALS = process.env.FIREBASE_CREDENTIALS || '{}';

let db;
let donations = [];

try {
  const serviceAccount = JSON.parse(FIREBASE_CREDENTIALS);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: FIREBASE_DB_URL
  });
  db = admin.database();
  console.log("[DonateGold] Firebase berhasil diinisialisasi.");
} catch (err) {
  console.error("[DonateGold] Gagal inisialisasi Firebase. Pastikan env var sudah benar.", err.message);
}

// Fungsi ini akan langsung menembak data ke database Cloud
function saveDonations(list) {
  if (db) {
    db.ref('donations').set(list).catch(err => console.error("Gagal simpan ke Firebase:", err));
  }
}

// Tiap platform donasi format field-nya beda-beda, jadi kita coba
// beberapa kemungkinan nama field yang umum dipakai.
function pick(obj, keys) {
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null && obj[k] !== '') return obj[k];
  }
  return undefined;
}

function normalizeDonation(source, body) {
  const name = pick(body, ['donator_name', 'name', 'supporter_name', 'from_name', 'sender_name', 'payer_name']) || 'Hamba Baik';
  const amountRaw = pick(body, ['amount_raw', 'amount', 'nominal', 'total_amount', 'amount_paid', 'price']);
  const message = pick(body, ['message', 'note', 'comment', 'supporter_message']) || '';
  const amount = Math.floor(Number(amountRaw) || 0);
  return {
    id: crypto.randomUUID(),
    source,
    name: String(name).slice(0, 40),
    amount,
    message: String(message).slice(0, 200),
    timestamp: Date.now(),
  };
}

// Cari tahu User ID Roblox dari nama yang diketik donatur di form Saweria/dll.
// Donatur diinstruksikan isi kolom "Nama" dengan USERNAME ROBLOX mereka persis.
async function resolveRobloxUser(claimedName) {
  if (!claimedName) return null;
  try {
    const resp = await fetch('https://users.roblox.com/v1/usernames/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernames: [claimedName], excludeBannedUsers: true }),
    });
    const json = await resp.json();
    const match = (json.data || [])[0];
    if (!match) return null; // nama tidak ketemu / typo / bukan username Roblox valid
    return { userId: match.id, username: match.name };
  } catch (err) {
    console.log('[DonateGold] Gagal resolve username Roblox:', err.message);
    return null;
  }
}

// Tempel hasil resolve Roblox ke donation sebelum disimpan.
async function finalizeDonation(donation) {
  const roblox = await resolveRobloxUser(donation.name);
  donation.robloxUserId = roblox ? roblox.userId : null;
  donation.robloxUsername = roblox ? roblox.username : null;
  return donation;
}
// Verifikasi signature khusus Saweria (opsional, aktif kalau SAWERIA_STREAM_KEY diisi).
// Kalau tidak diisi, keamanan tetap dijaga oleh SHARED_KEY di parameter URL.
function verifySaweriaSignature(req) {
  if (!SAWERIA_STREAM_KEY) return true;
  const sig = req.get('Saweria-Callback-Signature');
  if (!sig) return false;
  const expected = crypto.createHmac('sha256', SAWERIA_STREAM_KEY).update(req.rawBody).digest('hex');
  return sig === expected;
}

// Verifikasi khusus Tako: HMAC SHA-256 pada header X-Tako-Signature (sesuai dokumentasi resminya).
function verifyTakoSignature(req) {
  if (!TAKO_CALLBACK_SECRET) return true;
  const sig = req.get('X-Tako-Signature');
  if (!sig) return false;
  try {
    const expected = crypto.createHmac('sha256', TAKO_CALLBACK_SECRET).update(req.rawBody).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  } catch {
    return false;
  }
}

// Tako tidak mengirim nama/pesan donatur langsung di webhook, jadi perlu 1 API call
// tambahan ke endpoint resmi mereka untuk ambil detailnya.
async function fetchTakoGiftDetail(giftId) {
  const resp = await fetch(`https://tako.id/api/v1/gift/${giftId}`, {
    headers: {
      Authorization: `Bearer ${TAKO_API_KEY}`,
      'User-Agent': 'DonateGoldRelay/1.0',
    },
  });
  const json = await resp.json();
  return json.result || {};
}

// Rate limit sederhana biar tidak dispam / kebanjiran ke API Roblox (per IP, per menit).
const checkUsernameHits = new Map();
function isRateLimited(ip) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxHits = 20;
  const record = checkUsernameHits.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + windowMs;
  }
  record.count += 1;
  checkUsernameHits.set(ip, record);
  return record.count > maxHits;
}

// Endpoint PUBLIK (tanpa key) dipakai oleh halaman /checker.html untuk cek username
// Roblox sebelum donatur benar-benar donasi. Cuma baca data publik Roblox, aman diakses bebas.
app.get('/check-username', async (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi sebentar lagi.' });
  }

  const claimedName = String(req.query.name || '').trim();
  if (!claimedName) {
    return res.status(400).json({ error: 'Nama tidak boleh kosong.' });
  }
  if (claimedName.length > 20) {
    return res.status(400).json({ error: 'Username Roblox maksimal 20 karakter.' });
  }

  try {
    const roblox = await resolveRobloxUser(claimedName);
    if (!roblox) {
      return res.json({ found: false });
    }

    let avatarUrl = null;
    try {
      const thumbResp = await fetch(
        `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${roblox.userId}&size=150x150&format=Png&isCircular=false`
      );
      const thumbJson = await thumbResp.json();
      avatarUrl = (thumbJson.data && thumbJson.data[0] && thumbJson.data[0].imageUrl) || null;
    } catch (err) {
      console.log('[DonateGold] Gagal ambil thumbnail untuk preview:', err.message);
    }

    res.json({ found: true, userId: roblox.userId, username: roblox.username, avatarUrl });
  } catch (err) {
    console.log('[DonateGold] Gagal cek username:', err.message);
    res.status(500).json({ error: 'Gagal menghubungi server Roblox, coba lagi.' });
  }
});

// ==== Endpoint webhook: daftarkan URL ini di dashboard Saweria/Sosiabuzz/Tako ====
// Contoh: https://domain-kamu.com/webhook/saweria?key=SHARED_KEY
//         https://domain-kamu.com/webhook/sosiabuzz?key=SHARED_KEY
//         https://domain-kamu.com/webhook/tako?key=SHARED_KEY
app.post('/webhook/:source', async (req, res) => {
  const source = req.params.source.toLowerCase();

  if (req.query.key !== SHARED_KEY) {
    return res.status(401).json({ status: 'failed', error: 'unauthorized' });
  }
  if (source === 'saweria' && !verifySaweriaSignature(req)) {
    return res.status(401).json({ status: 'failed', error: 'invalid signature' });
  }


  // ==== Jalur khusus Bagibagi.co (Mendukung Login Roblox / Nama Manual) ====
  if (source === 'bagibagi') {
    const body = req.body || {};
    // Bagibagi biasanya mengirim payload nominal dengan field `amount` atau `amount_raw`
    let amount = Number(body.amount) || Number(body.amount_raw) || 0;
    let name = body.donor_name || body.name || 'Hamba Baik';
    let message = body.message || body.notes || '';
    
    const donation = {
      id: crypto.randomUUID(),
      source: 'bagibagi',
      name: String(name).slice(0, 40),
      amount: Math.floor(amount),
      message: String(message).slice(0, 200),
      timestamp: Date.now(),
    };

    if (donation.amount <= 0) {
      return res.status(400).json({ status: 'failed', error: 'amount tidak valid' });
    }

    // Cek apakah penonton login pakai integrasi Roblox (ada roblox_id dari Bagibagi)
    if (body.roblox_id || body.robloxUserId) {
        // Langsung tetapkan ID-nya tanpa perlu API lookup lagi
        donation.robloxUserId = Number(body.roblox_id || body.robloxUserId);
        donation.robloxUsername = body.roblox_username || donation.name;
    } else {
        // Jika penonton ketik manual, server akan otomatis mencari ID-nya 
        // menggunakan fungsi resolveRobloxUser yang sudah ada di script kamu
        await finalizeDonation(donation);
    }

    donations.push(donation);
    saveDonations(donations);
    console.log(`[DonateGold] Donasi baru dari bagibagi: ${donation.name} - Rp${donation.amount}`);
    return res.json({ status: 'ok' });
  }
  
  // ==== Jalur khusus Tako: format payload beda total dari Saweria/Sosiabuzz ====
  if (source === 'tako') {
    if (!verifyTakoSignature(req)) {
      return res.status(401).json({ status: 'failed', error: 'invalid signature' });
    }

    const body = req.body || {};
    if (body.event !== 'payment.success') {
      return res.json({ status: 'ignored', reason: 'event bukan payment.success' });
    }

    const data = body.data || {};
    if (!data.relatedGiftId) {
      // Ini top up saldo pribadi si creator, bukan hadiah dari orang lain — jangan dianggap donasi.
      return res.json({ status: 'ignored', reason: 'top up saldo, bukan hadiah donasi' });
    }

    let name = 'Hamba Baik';
    let message = '';
    try {
      const gift = await fetchTakoGiftDetail(data.relatedGiftId);
      name = gift.gifterName || name;
      message = gift.message || '';
    } catch (err) {
      console.log('[DonateGold] Gagal ambil detail gift Tako:', err.message);
    }

    const donation = {
      id: crypto.randomUUID(),
      source: 'tako',
      name: String(name).slice(0, 40),
      amount: Math.floor(Number(data.amount) || 0),
      message: String(message).slice(0, 200),
      timestamp: Date.now(),
    };

    if (!donation.amount || donation.amount <= 0) {
      return res.status(400).json({ status: 'failed', error: 'amount tidak valid' });
    }

    await finalizeDonation(donation);
    donations.push(donation);
    saveDonations(donations);
    console.log(`[DonateGold] Donasi baru dari tako: ${donation.name} - Rp${donation.amount}`);
    return res.json({ status: 'ok' });
  }

  // ==== Jalur umum: Saweria, Sosiabuzz, dan platform lain dengan payload sederhana ====
  const donation = normalizeDonation(source, req.body || {});
  if (!donation.amount || donation.amount <= 0) {
    console.log(`[DonateGold] Payload ditolak (amount tidak terbaca) dari ${source}:`, JSON.stringify(req.body));
    return res.status(400).json({ status: 'failed', error: 'amount tidak valid' });
  }

  await finalizeDonation(donation);
  donations.push(donation);
  saveDonations(donations);
  console.log(`[DonateGold] Donasi baru dari ${source}: ${donation.name} - Rp${donation.amount}`);
  res.json({ status: 'ok' });
});

// Endpoint untuk kirim donasi TES tanpa transaksi asli (buat cek sistem jalan atau tidak)
// Contoh body: { "source": "test", "name": "Budi", "amount": 10000, "message": "semangat!" }
// Ganti /test-donate menjadi nama jalur rahasiamu sendiri
app.post('/pancingan-rahasia-shiro', async (req, res) => {
  // Gembok 1: Kunci di URL (seperti biasa)
  if (req.query.key !== ROBLOX_KEY) return res.status(401).json({ error: 'unauthorized' });

  // GEMBOK 2: Kunci di dalam Header (Ini pelindung ke-2 nya!)
  if (req.headers['x-shiro-secret'] !== 'N6OXTlagkjTGz07Bx6mf') {
      return res.status(401).json({ error: 'Akses ditolak: Header salah!' });
  }

  const donation = normalizeDonation(req.body.source || 'test', req.body || {});
  
  await finalizeDonation(donation); 
  
  donations.push(donation);
  saveDonations(donations);
  res.json({ status: 'ok', donation });
});

// Lihat isi data mentah (buat ngecek/debug, tanpa perlu akses file server langsung).
// Buka saja URL ini di browser: https://domain-kamu.com/admin/raw?key=ISI_ADMIN_KEY
app.get('/admin/raw', (req, res) => {
  if (req.query.key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
  res.json({ total_entries: donations.length, donations });
});

// Kosongkan SEMUA data donasi (total & harian ikut hilang, tidak bisa dikembalikan).
// Contoh: curl -X POST "https://domain-kamu.com/admin/reset?key=ISI_ADMIN_KEY"
app.post('/admin/reset', (req, res) => {
  if (req.query.key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
  donations = [];
  saveDonations(donations);
  console.log('[DonateGold] Semua data donasi telah direset oleh admin.');
  res.json({ status: 'ok', message: 'Semua data donasi sudah dikosongkan.' });
});

// Kosongkan HANYA data hari ini (total keseluruhan tetap utuh).
// Berguna kalau mau leaderboard harian mulai dari 0 lebih awal dari reset otomatis jam 00:00 WIB.
app.post('/admin/reset-daily', (req, res) => {
  if (req.query.key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
  const now = Date.now();
  donations = donations.filter(d => !isSameDayWIB(d.timestamp, now));
  saveDonations(donations);
  console.log('[DonateGold] Data donasi hari ini telah direset oleh admin.');
  res.json({ status: 'ok', message: 'Leaderboard harian sudah dikosongkan.' });
});

function isSameDayWIB(ts, ref) {
  const toWIBDateString = (ms) => new Date(ms + 7 * 3600 * 1000).toISOString().slice(0, 10);
  return toWIBDateString(ts) === toWIBDateString(ref);
}

function buildLeaderboard(list) {
  const totals = {}; // key -> { name, robloxUserId, amount }
  for (const d of list) {
    const key = d.robloxUserId ? `id:${d.robloxUserId}` : `name:${d.name}`;
    if (!totals[key]) {
      totals[key] = { name: d.robloxUsername || d.name, robloxUserId: d.robloxUserId || null, amount: 0 };
    }
    totals[key].amount += d.amount;
  }
  return Object.values(totals).sort((a, b) => b.amount - a.amount);
}

// Total keseluruhan donasi milik 1 donatur (dipakai buat ditampilkan di notifikasi:
// "Total donasi kamu sejauh ini: RpXXX", bukan cuma nominal donasi barusan).
function totalsByKey(list) {
  const totals = {};
  for (const d of list) {
    const key = d.robloxUserId ? `id:${d.robloxUserId}` : `name:${d.name}`;
    totals[key] = (totals[key] || 0) + d.amount;
  }
  return totals;
}

// ==== Endpoint yang di-polling oleh Roblox ====
// GET /donategold/state?key=ROBLOX_KEY&since=<timestamp_ms_terakhir>
app.get('/donategold/state', (req, res) => {
  if (req.query.key !== ROBLOX_KEY) return res.status(401).json({ error: 'unauthorized' });

  const since = Number(req.query.since) || 0;
  const now = Date.now();
  const dailyList = donations.filter(d => isSameDayWIB(d.timestamp, now));
  const totalMap = totalsByKey(donations);

  const newEvents = donations
    .filter(d => d.timestamp > since)
    .map(d => {
      const key = d.robloxUserId ? `id:${d.robloxUserId}` : `name:${d.name}`;
      return { ...d, totalToDate: totalMap[key] || d.amount };
    });

  res.json({
    now,
    newEvents,
    leaderboardAllTime: buildLeaderboard(donations).slice(0, 10),
    leaderboardDaily: buildLeaderboard(dailyList).slice(0, 10),
  });
});

app.get('/', (req, res) => res.send('DonateGold relay is running.'));

// Memastikan server menyedot riwayat donasi dari Firebase sebelum membuka pintu
if (db) {
  db.ref('donations').once('value', (snapshot) => {
    donations = snapshot.val() || [];
    console.log(`[DonateGold] Berhasil memuat ${donations.length} donasi dari Firebase.`);
    app.listen(PORT, () => console.log(`DonateGold relay Tempat Sementara jalan di port ${PORT}`));
  });
} else {
  app.listen(PORT, () => console.log(`DonateGold relay jalan di port ${PORT} (Tanpa Firebase)`));
}
