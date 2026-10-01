# Timeline Aktivitas Karyawan (live, real time)

**Mode default: TANPA LOGIN.** Siapa pun yang punya link bisa melihat dan mengubah data, dan perubahan muncul real time di semua layar. Jangan bagikan link ke sembarang orang. Server menyimpan backup harian otomatis (14 hari terakhir) di `DATA_DIR`.
Untuk mengaktifkan daftar/login dan peran (Super Admin, dst.), set variabel `REQUIRE_LOGIN=1`; akun pertama yang mendaftar menjadi Super Admin.

Butuh **Node.js 18 atau lebih baru**. Tidak ada library yang perlu diinstal.

## Jalankan di komputer sendiri
    node server.js
Buka http://localhost:3000. **Akun pertama yang mendaftar otomatis menjadi Super Admin**, jadi daftar sendiri dulu sebelum membagikan alamatnya.

## Peran
- Super Admin: semua akses + menu "Kelola pengguna" (ubah peran, hapus akun)
- Admin (editor): tambah, ubah, hapus agenda
- Anggota: centang agenda selesai dan isi laporan (budget realisasi, kepuasan, impact)
- Viewer: hanya melihat. Pendaftar baru otomatis Viewer; naikkan perannya di "Kelola pengguna".

## Agar bisa diakses semua orang (online)
1. Taruh folder ini di hosting yang mendukung Node.js (Railway, Render, Fly.io, atau VPS).
2. Perintah start: `node server.js`.
3. WAJIB pasang **penyimpanan permanen** (volume/disk) dan arahkan `DATA_DIR` ke sana, kalau tidak data hilang saat server restart.
4. Aktifkan HTTPS (otomatis di Railway/Render) dan set `COOKIE_SECURE=1`.
5. `PORT` biasanya diatur otomatis oleh hosting.

Data tersimpan di `DATA_DIR/db.json` (password di-hash dengan scrypt). Backup file itu secara berkala.
