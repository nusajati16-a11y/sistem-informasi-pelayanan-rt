# Panduan Migrasi Database dari SQLite ke MySQL

## Langkah-langkah Migrasi

### 1. Install Dependencies
Pastikan MySQL/MariaDB sudah berjalan di XAMPP, lalu install dependency baru:

```bash
npm install
```

Ini akan menginstall `mysql2` yang diperlukan untuk koneksi MySQL.

### 2. Setup Database MySQL

1. Buka phpMyAdmin di browser: `http://localhost/phpmyadmin`
2. Buat database baru dengan nama `sistem_informasi_rt` (opsional, akan dibuat otomatis)
3. Atau jalankan file SQL secara manual:
   - Buka file `database.sql`
   - Copy semua isinya
   - Paste di SQL tab di phpMyAdmin
   - Klik "Go" untuk menjalankan

### 3. Konfigurasi Database

Edit file `db-config.js` dan sesuaikan dengan konfigurasi MySQL Anda:

```javascript
const dbConfig = {
  host: 'localhost',
  user: 'root',          // Sesuaikan jika berbeda
  password: '',          // Isi password MySQL jika ada
  database: 'sistem_informasi_rt',
  // ...
};
```

### 4. Migrasi Data (Opsional)

Jika Anda memiliki data di SQLite yang ingin dipindahkan ke MySQL:

1. Export data dari SQLite ke CSV atau SQL
2. Import ke MySQL melalui phpMyAdmin atau command line

**Catatan:** Database akan diinisialisasi otomatis saat server pertama kali dijalankan dengan tabel kosong. Admin default akan dibuat:
- NIK: `0000000000000000`
- Email: `admin@rt.local`
- Password: `admin123`

### 5. Jalankan Server

```bash
npm start
```

Server akan:
- Membuat database jika belum ada
- Membuat semua tabel jika belum ada
- Membuat user admin default jika belum ada

## Perubahan yang Dilakukan

### Database Format
- **Sebelum:** SQLite (file `database.db`)
- **Sesudah:** MySQL/MariaDB (database `sistem_informasi_rt`)

### File yang Berubah
1. `database.sql` - Schema database MySQL baru
2. `db-config.js` - Konfigurasi dan wrapper untuk MySQL
3. `server.js` - Menggunakan MySQL wrapper
4. `package.json` - Dependency `mysql2` ditambahkan, `sqlite3` dihapus

### Perbedaan Fitur
- Field `details` di tabel `letter_applications` sekarang menggunakan tipe JSON native MySQL
- Foreign keys diaktifkan secara default
- Indexing yang lebih baik untuk performa

## Troubleshooting

### Error: "Access denied for user"
- Pastikan MySQL service berjalan di XAMPP
- Cek username dan password di `db-config.js`

### Error: "Unknown database"
- Database akan dibuat otomatis saat server dijalankan
- Atau buat manual melalui phpMyAdmin

### Error: "Table already exists"
- Tidak masalah, server akan skip pembuatan tabel yang sudah ada

## Rollback ke SQLite (Jika Perlu)

Jika ingin kembali ke SQLite:
1. Kembalikan file `server.js` dari backup
2. Install `sqlite3`: `npm install sqlite3`
3. Hapus dependency `mysql2` dari `package.json`

