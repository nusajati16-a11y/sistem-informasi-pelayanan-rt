# Sistem Informasi Pelayanan Terpadu Administrasi Warga RT

Sistem informasi untuk pelayanan administrasi warga di lingkungan Rukun Tetangga (RT).

## Fitur

- **Halaman Utama**: Dapat diakses tanpa login
- **Registrasi**: Pendaftaran akun dengan NIK, email, nomor telepon, dan password
- **Login**: Autentikasi menggunakan NIK (sebagai username) dan password
- **Dashboard**: Halaman utama setelah login
- **Layanan**: Halaman layanan administrasi (memerlukan login)
- **Profil**: Informasi profil pengguna (memerlukan login)

## Teknologi

- **Backend**: Node.js dengan Express
- **Database**: SQLite
- **Authentication**: Session-based dengan bcrypt untuk enkripsi password
- **Frontend**: HTML, CSS, JavaScript vanilla

## Instalasi

1. Install dependencies:
```bash
npm install
```

2. Jalankan server:
```bash
npm start
```

Atau untuk development dengan auto-reload:
```bash
npm run dev
```

3. Buka browser dan akses:
```
http://localhost:3000
```

## Struktur Proyek

```
.
├── server.js          # Server Express dan API routes
├── package.json       # Dependencies dan scripts
├── database.db        # Database SQLite (auto-generated)
├── public/
│   ├── index.html     # Halaman utama
│   ├── login.html     # Halaman login
│   ├── register.html  # Halaman registrasi
│   ├── dashboard.html # Dashboard setelah login
│   ├── layanan.html   # Halaman layanan
│   ├── profil.html    # Halaman profil
│   ├── styles.css     # Styling
│   └── script.js      # JavaScript utilities
└── README.md
```

## API Endpoints

### Public
- `GET /` - Halaman utama
- `GET /login` - Halaman login
- `GET /register` - Halaman registrasi

### Protected (memerlukan login)
- `GET /dashboard` - Dashboard pengguna
- `GET /layanan` - Halaman layanan
- `GET /profil` - Halaman profil

### API Routes
- `POST /api/register` - Registrasi pengguna baru
- `POST /api/login` - Login pengguna
- `POST /api/logout` - Logout pengguna
- `GET /api/user` - Mendapatkan informasi pengguna saat ini

## Validasi

### Registrasi
- NIK: Harus 16 digit angka, unik
- Email: Format email valid, unik
- Nomor Telepon: Format nomor telepon Indonesia
- Password: Minimal 6 karakter

### Login
- NIK: 16 digit angka
- Password: Sesuai dengan yang didaftarkan

## Catatan

- Database SQLite akan dibuat otomatis saat pertama kali menjalankan server
- Session disimpan di server dengan durasi 24 jam
- Password dienkripsi menggunakan bcrypt sebelum disimpan ke database

