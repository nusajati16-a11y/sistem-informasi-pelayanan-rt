# Troubleshooting - Masalah Database

## Masalah: Server tidak bisa berjalan setelah database.db dihapus

### Penyebab Umum:

1. **MySQL/MariaDB belum berjalan di XAMPP**
   - Solusi: Buka XAMPP Control Panel, klik "Start" pada MySQL/MariaDB
   - Pastikan status MySQL menunjukkan "Running"

2. **Password MySQL tidak sesuai**
   - Solusi: Edit file `db-config.js` dan sesuaikan password:
   ```javascript
   const dbConfig = {
     host: 'localhost',
     user: 'root',
     password: 'password_anda', // Sesuaikan dengan password MySQL
     database: 'sistem_informasi_rt',
     // ...
   };
   ```

3. **Port MySQL berubah atau terpakai**
   - Default port MySQL: 3306
   - Cek di XAMPP apakah port berbeda

4. **Database belum dibuat**
   - Solusi: Server akan membuat database otomatis saat pertama kali dijalankan
   - Atau buat manual melalui phpMyAdmin: `http://localhost/phpmyadmin`

### Cara Cek Masalah:

1. **Test koneksi MySQL:**
   ```bash
   # Buka Command Prompt/Terminal
   mysql -u root -p
   # Tekan Enter jika password kosong
   ```

2. **Cek log error:**
   - Lihat output di terminal saat menjalankan `npm start`
   - Error biasanya muncul saat inisialisasi database

3. **Cek apakah MySQL service berjalan:**
   - Windows: Buka Services (services.msc), cari "MySQL"
   - XAMPP: Buka XAMPP Control Panel, pastikan MySQL status "Running"

### Error Messages Umum:

#### `ECONNREFUSED`
- **Penyebab:** MySQL service tidak berjalan
- **Solusi:** Start MySQL di XAMPP Control Panel

#### `ER_ACCESS_DENIED_ERROR`
- **Penyebab:** Username/password MySQL salah
- **Solusi:** Update `db-config.js` dengan credentials yang benar

#### `ER_BAD_DB_ERROR`
- **Penyebab:** Database belum dibuat
- **Solusi:** Server akan membuat otomatis, atau buat manual via phpMyAdmin

#### `Cannot find module 'mysql2'`
- **Penyebab:** Dependency belum diinstall
- **Solusi:** Jalankan `npm install`

### Verifikasi Setup:

1. Pastikan semua dependency terinstall:
   ```bash
   npm install
   ```

2. Pastikan MySQL berjalan:
   - XAMPP Control Panel → MySQL → Status "Running"

3. Test koneksi:
   - Buka phpMyAdmin: `http://localhost/phpmyadmin`
   - Harus bisa login dengan user `root` dan password kosong (default)

4. Jalankan server:
   ```bash
   npm start
   ```

5. Cek output terminal:
   - Harus muncul: `✅ Database initialized successfully`
   - Harus muncul: `🚀 Server berjalan di http://localhost:3000`

### Jika Masih Bermasalah:

1. Hapus database lama (jika ada):
   - Buka phpMyAdmin
   - Drop database `sistem_informasi_rt`
   - Server akan membuat ulang otomatis

2. Reset konfigurasi:
   - Pastikan `db-config.js` menggunakan default:
     - host: 'localhost'
     - user: 'root'
     - password: '' (kosong untuk XAMPP default)

3. Cek file `database.sql`:
   - Pastikan file ada di root folder
   - Pastikan syntax SQL valid

