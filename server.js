const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const QRCode = require('qrcode');
const db = require('./db-config');

const app = express();
const PORT = 3000;
const LETTER_TYPES = ['death', 'birth', 'mutation', 'other'];

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  maxAge: 0,
  setHeaders: (res) => {
    res.set('Cache-Control', 'no-store');
  }
}));
// Static untuk file upload (bukti pembayaran, lampiran surat, dll.)
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  etag: false,
  maxAge: 0,
  setHeaders: (res) => {
    res.set('Cache-Control', 'no-store');
  }
}));
// Fallback route untuk memastikan file upload bisa diakses meskipun path mengandung spasi/karakter khusus
app.get('/uploads/*', (req, res) => {
  // Get the full path after /uploads/
  const filePath = req.params[0] || req.path.replace('/uploads/', '');
  const fullPath = path.join(__dirname, 'uploads', filePath);

  if (!fs.existsSync(fullPath)) {
    console.error('File not found:', fullPath);
    return res.status(404).send('File tidak ditemukan');
  }

  res.sendFile(fullPath);
});

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Session configuration
app.use(session({
  secret: 'sistem-rt-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set to true if using HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize database before starting server
(async () => {
  try {
    await db.initialize();
    console.log('✅ Database ready');
    
    // Start server after database is ready
    app.listen(PORT, () => {
      console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('❌ Failed to initialize database:', error.message);
    console.error('💡 Pastikan MySQL/MariaDB sudah berjalan di XAMPP');
    process.exit(1);
  }
})();

// Middleware to check authentication
const requireAuth = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ error: 'Anda harus login terlebih dahulu' });
  }
};

// Middleware to check admin role
const requireAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Akses ditolak. Hanya administrator yang dapat mengakses.' });
  }
};

// Routes

// Home page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login page
app.get('/login', (req, res) => {
  if (req.session.user) {
    // Redirect admin to /admin, other users to /home
    if (req.session.user.role === 'admin') {
      return res.redirect('/admin');
    }
    return res.redirect('/home');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Register page
app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/home');
  }
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Home page (protected) - shows news and announcements
app.get('/home', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Dashboard / Menu page
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Menu route (alias for dashboard)
app.get('/menu', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Letter application pages
app.get('/pengajuan-surat', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pengajuan-surat.html'));
});

app.get('/pengajuan-surat/:type', requireAuth, (req, res) => {
  const { type } = req.params;
  if (!LETTER_TYPES.includes(type)) {
    return res.redirect('/pengajuan-surat');
  }
  return res.redirect(`/form-surat?type=${type}`);
});

app.get('/form-surat', requireAuth, (req, res) => {
  const { type } = req.query;
  if (!type || !LETTER_TYPES.includes(type)) {
    return res.redirect('/pengajuan-surat');
  }
  res.sendFile(path.join(__dirname, 'public', 'form-surat.html'));
});

// Payment page
app.get('/pembayaran-iuran', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pembayaran-iuran.html'));
});

// Admin pages
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/pengajuan-surat', requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-pengajuan.html'));
});

// API Routes

// Register API
app.post('/api/register', async (req, res) => {
  const { 
    nik, email, phone, password, 
    full_name, place_of_birth, date_of_birth, gender,
    address, rt, rw, kelurahan, kecamatan, city, province, postal_code
  } = req.body;

  // Validation
  if (!nik || !email || !phone || !password || !full_name || !full_name.trim() ||
      !place_of_birth || !place_of_birth.trim() || !date_of_birth ||
      !gender || !address || !address.trim() ||
      !rt || !rt.toString().trim() || !rw || !rw.toString().trim() ||
      !kelurahan || !kelurahan.trim() || !kecamatan || !kecamatan.trim() ||
      !city || !city.trim() || !province || !province.trim() ||
      !postal_code || !postal_code.toString().trim()) {
    return res.status(400).json({ error: 'Semua field wajib harus diisi' });
  }

  if (!['laki-laki', 'perempuan'].includes(gender)) {
    return res.status(400).json({ error: 'Jenis kelamin tidak valid' });
  }

  // Validate NIK format (16 digits)
  if (!/^\d{16}$/.test(nik)) {
    return res.status(400).json({ error: 'NIK harus terdiri dari 16 digit angka' });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Format email tidak valid' });
  }

  // Validate phone format (Indonesian phone number)
  if (!/^(\+62|62|0)[0-9]{9,12}$/.test(phone)) {
    return res.status(400).json({ error: 'Format nomor telepon tidak valid' });
  }

  const numericRtRwRegex = /^\d{1,3}$/;
  if (!numericRtRwRegex.test(rt) || !numericRtRwRegex.test(rw)) {
    return res.status(400).json({ error: 'RT/RW harus berupa angka 1-3 digit' });
  }

  if (!/^\d{5}$/.test(postal_code)) {
    return res.status(400).json({ error: 'Kode pos harus terdiri dari 5 digit angka' });
  }

  // Check if NIK already exists
  db.get('SELECT * FROM users WHERE nik = ?', [nik], async (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
    if (row) {
      return res.status(400).json({ error: 'NIK sudah terdaftar' });
    }

    // Check if email already exists
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Terjadi kesalahan server' });
      }
      if (row) {
        return res.status(400).json({ error: 'Email sudah terdaftar' });
      }

      // Hash password
      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert user with extended data
        const cleanFullName = full_name.trim();
        const cleanPlaceOfBirth = place_of_birth.trim();
        const cleanAddress = address.trim();
        const cleanRt = String(rt).trim();
        const cleanRw = String(rw).trim();
        const cleanKelurahan = kelurahan.trim();
        const cleanKecamatan = kecamatan.trim();
        const cleanCity = city.trim();
        const cleanProvince = province.trim();
        const cleanPostalCode = String(postal_code).trim();

        db.run(
          `INSERT INTO users (nik, email, phone, password, full_name, place_of_birth, 
           date_of_birth, gender, address, rt, rw, kelurahan, kecamatan, city, province, postal_code) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [nik, email, phone, hashedPassword, cleanFullName, cleanPlaceOfBirth, 
           date_of_birth || null, gender, cleanAddress, cleanRt, cleanRw,
           cleanKelurahan, cleanKecamatan, cleanCity, cleanProvince, cleanPostalCode],
          function(err) {
            if (err) {
              return res.status(500).json({ error: 'Gagal mendaftarkan pengguna' });
            }
            res.json({ 
              success: true, 
              message: 'Registrasi berhasil! Silakan login.',
              userId: this.lastID 
            });
          }
        );
      } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan saat enkripsi password' });
      }
    });
  });
});

// Login API
app.post('/api/login', (req, res) => {
  const { nik, password } = req.body;

  if (!nik || !password) {
    return res.status(400).json({ error: 'NIK dan password harus diisi' });
  }

  db.get('SELECT * FROM users WHERE nik = ?', [nik], async (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
    if (!row) {
      return res.status(401).json({ error: 'NIK atau password salah' });
    }

    try {
      const match = await bcrypt.compare(password, row.password);
      if (match) {
        // Pastikan selalu ada nama yang bisa ditampilkan di UI
        const safeFullName = (row.full_name && row.full_name.trim()) ? row.full_name.trim() : row.nik;
        req.session.user = {
          id: row.id,
          nik: row.nik,
          email: row.email,
          phone: row.phone,
          role: row.role || 'user',
          full_name: safeFullName
        };
        res.json({ 
          success: true, 
          message: 'Login berhasil',
          user: req.session.user
        });
      } else {
        res.status(401).json({ error: 'NIK atau password salah' });
      }
    } catch (error) {
      res.status(500).json({ error: 'Terjadi kesalahan saat verifikasi password' });
    }
  });
});

// Logout API
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal logout' });
    }
    res.json({ success: true, message: 'Logout berhasil' });
  });
});

// Get current user API
app.get('/api/user', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Tidak ada sesi aktif' });
  }

  const ensureResponse = (user) => res.json({ user });
  const current = req.session.user;
  const hasName = current.full_name && current.full_name.toString().trim().length > 0;

  if (hasName) {
    current.full_name = current.full_name.toString().trim();
    return ensureResponse(current);
  }

  db.get('SELECT full_name, nik FROM users WHERE id = ?', [current.id], (err, row) => {
    if (err) {
      current.full_name = current.nik;
      return ensureResponse(current);
    }

    if (row) {
      const safeName = row.full_name && row.full_name.trim().length > 0 ? row.full_name.trim() : row.nik;
      current.full_name = safeName;
    } else {
      current.full_name = current.nik;
    }

    ensureResponse(current);
  });
});

app.get('/profil', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profil.html'));
});

// API Routes - News and Announcements
// Public endpoint for news (accessible without login)
app.get('/api/news', (req, res) => {
  const type = req.query.type;
  let query = 'SELECT * FROM news';
  const params = [];
  
  if (type && type !== 'all') {
    query += ' WHERE type = ?';
    params.push(type);
  }
  
  query += ' ORDER BY published_date DESC, created_at DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal memuat berita' });
    }
    // Ensure image_path is properly formatted for frontend
    const news = rows.map(row => {
      // Log all fields to debug
      console.log('Raw news row:', {
        id: row.id,
        title: row.title,
        image_path: row.image_path,
        has_image_path: !!row.image_path
      });
      
      if (row.image_path && row.image_path.trim() !== '' && row.image_path !== 'null') {
        // Normalize path - ensure it starts with uploads/
        let imagePath = String(row.image_path).trim();
        // Remove any leading slashes or backslashes
        imagePath = imagePath.replace(/^[\/\\]+/, '');
        // Ensure it starts with uploads/
        if (!imagePath.startsWith('uploads/')) {
          imagePath = 'uploads/' + imagePath;
        }
        // Remove duplicate uploads/ if exists
        imagePath = imagePath.replace(/^uploads\/uploads\//, 'uploads/');
        row.image_path = imagePath;
        console.log('Formatted image path for:', row.title, '->', imagePath);
      } else {
        // Clear image_path if it's empty or null
        row.image_path = null;
      }
      return row;
    });
    res.json({ news });
  });
});

app.post('/api/news', requireAuth, requireAdmin, upload.single('image'), (req, res) => {
  const { title, content, type, published_date } = req.body;
  
  if (!title || !content || !type || !published_date) {
    return res.status(400).json({ error: 'Semua field wajib harus diisi' });
  }
  
  // Get image path - multer stores path relative to project root (e.g., "uploads/filename.jpg")
  const imagePath = req.file ? req.file.path.replace(/\\/g, '/') : null;
  
  if (imagePath) {
    console.log('Saving image path:', imagePath);
  }
  
  // Insert news with image_path
  db.run(
    'INSERT INTO news (title, content, type, published_date, author_id, image_path) VALUES (?, ?, ?, ?, ?, ?)',
    [title, content, type, published_date, req.session.user.id, imagePath],
    function(err) {
      if (err) {
        console.error('Error inserting news:', err.message);
        // If column doesn't exist, try to add it and retry
        if (err.message && (err.message.includes('image_path') || err.message.includes('Unknown column'))) {
          console.log('⚠️  image_path column not found, attempting to add it...');
          // Try to add column
          db.run('ALTER TABLE news ADD COLUMN image_path VARCHAR(500) NULL AFTER content', [], function(alterErr) {
            if (alterErr && !alterErr.message.includes('Duplicate column')) {
              console.error('Failed to add image_path column:', alterErr.message);
              // Fallback: insert without image_path
              db.run(
                'INSERT INTO news (title, content, type, published_date, author_id) VALUES (?, ?, ?, ?, ?)',
                [title, content, type, published_date, req.session.user.id],
                function(err2) {
                  if (err2) {
                    return res.status(500).json({ error: 'Gagal mempublikasikan berita' });
                  }
                  handleNewsSuccess(this.lastID);
                }
              );
            } else {
              // Column added, retry insert
              console.log('✅ image_path column added, retrying insert...');
              db.run(
                'INSERT INTO news (title, content, type, published_date, author_id, image_path) VALUES (?, ?, ?, ?, ?, ?)',
                [title, content, type, published_date, req.session.user.id, imagePath],
                function(retryErr) {
                  if (retryErr) {
                    return res.status(500).json({ error: 'Gagal mempublikasikan berita setelah menambahkan kolom' });
                  }
                  handleNewsSuccess(this.lastID);
                }
              );
            }
          });
        } else {
          return res.status(500).json({ error: 'Gagal mempublikasikan berita: ' + err.message });
        }
      } else {
        handleNewsSuccess(this.lastID);
      }
      
      function handleNewsSuccess(newsId) {
        // Create notification for all users
        db.all('SELECT id FROM users WHERE role != ?', ['admin'], (err, users) => {
          if (!err && users) {
            users.forEach(user => {
              db.run(
                'INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, ?, ?, ?, ?)',
                [user.id, 'news', 'Berita/Pengumuman Baru', title, '/home']
              );
            });
          }
        });
        
        res.json({ success: true, message: 'Berita berhasil dipublikasikan', id: newsId });
      }
    }
  );
});

app.delete('/api/news/:id', requireAuth, requireAdmin, (req, res) => {
  db.run('DELETE FROM news WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Gagal menghapus berita' });
    }
    res.json({ success: true });
  });
});

// API Routes - Letter Applications
app.post('/api/letter-applications', requireAuth, upload.single('attachment'), (req, res) => {
  const { letter_type, purpose, details } = req.body;
  const userId = req.session.user.id;
  
  if (!letter_type) {
    return res.status(400).json({ error: 'Jenis surat harus dipilih' });
  }
  if (!LETTER_TYPES.includes(letter_type)) {
    return res.status(400).json({ error: 'Jenis surat tidak valid' });
  }
  
  // Generate application ID
  const applicationId = 'SRT-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5).toUpperCase();
  
  let parsedDetails = null;
  if (details) {
    try {
      parsedDetails = JSON.parse(details);
    } catch (error) {
      return res.status(400).json({ error: 'Format detail pengajuan tidak valid' });
    }
  }

  const attachmentPath = req.file ? req.file.path : null;
  
  // MySQL JSON column can accept JSON directly or string
  const detailsValue = parsedDetails ? JSON.stringify(parsedDetails) : null;
  
  db.run(
    `INSERT INTO letter_applications (user_id, letter_type, purpose, details, attachment_path, application_id) 
     VALUES (?, ?, ?, ?, ?, ?)`,
    [userId, letter_type, purpose || null, detailsValue, attachmentPath, applicationId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Gagal mengajukan surat' });
      }
      
      // Create notification for admin
      db.all('SELECT id FROM users WHERE role = ?', ['admin'], (err, admins) => {
        if (!err && admins) {
          admins.forEach(admin => {
            db.run(
              'INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, ?, ?, ?, ?)',
              [admin.id, 'application', 'Pengajuan Surat Baru', `Pengajuan surat baru dengan ID: ${applicationId}`, '/admin']
            );
          });
        }
      });
      
      res.json({ 
        success: true, 
        message: 'Pengajuan berhasil',
        application_id: applicationId,
        id: this.lastID || this.insertId
      });
    }
  );
});

app.get('/api/letter-applications', requireAuth, requireAdmin, (req, res) => {
  db.all(
    `SELECT la.*, u.nik as user_nik, u.full_name as user_name 
     FROM letter_applications la 
     JOIN users u ON la.user_id = u.id 
     ORDER BY la.created_at DESC`,
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat pengajuan' });
      }
      res.json({ applications: rows.map(parseApplicationRow) });
    }
  );
});

app.get('/api/letter-applications/my', requireAuth, (req, res) => {
  db.all(
    'SELECT * FROM letter_applications WHERE user_id = ? ORDER BY created_at DESC',
    [req.session.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat pengajuan' });
      }
      res.json({ applications: rows.map(parseApplicationRow) });
    }
  );
});

app.get('/api/letter-applications/:id', requireAuth, (req, res) => {
  db.get(
    `SELECT la.*, u.nik as user_nik, u.full_name as user_name, u.email as user_email, 
     u.phone as user_phone, u.place_of_birth, u.date_of_birth, u.gender, 
     u.address, u.rt, u.rw, u.kelurahan, u.kecamatan, u.city, u.province, u.postal_code
     FROM letter_applications la 
     JOIN users u ON la.user_id = u.id 
     WHERE la.id = ?`,
    [req.params.id],
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat detail' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Pengajuan tidak ditemukan' });
      }
      // Check if user is admin or owner
      if (req.session.user.role !== 'admin' && row.user_id !== req.session.user.id) {
        return res.status(403).json({ error: 'Akses ditolak' });
      }
      res.json({ application: parseApplicationRow(row) });
    }
  );
});

app.post('/api/letter-applications/:id/approve', requireAuth, requireAdmin, (req, res) => {
  db.get('SELECT * FROM letter_applications WHERE id = ?', [req.params.id], (err, app) => {
    if (err || !app) {
      return res.status(404).json({ error: 'Pengajuan tidak ditemukan' });
    }
    
    // Get user data
    db.get('SELECT * FROM users WHERE id = ?', [app.user_id], (err, user) => {
      if (err || !user) {
        return res.status(500).json({ error: 'Gagal memuat data pengguna' });
      }
      
      // Generate PDF
      generateLetterPDF(app, user, (pdfPath) => {
        // Update application
        db.run(
          'UPDATE letter_applications SET status = ?, pdf_path = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
          ['approved', pdfPath, req.params.id],
          (err) => {
            if (err) {
              return res.status(500).json({ error: 'Gagal menyetujui pengajuan' });
            }
            
            // Create notification for user
            db.run(
              'INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, ?, ?, ?, ?)',
              [app.user_id, 'application', 'Pengajuan Disetujui', `Pengajuan surat Anda (ID: ${app.application_id}) telah disetujui. Surat siap diunduh.`, '/home']
            );
            
            res.json({ success: true, message: 'Pengajuan disetujui', pdf_path: pdfPath });
          }
        );
      });
    });
  });
});

app.post('/api/letter-applications/:id/reject', requireAuth, requireAdmin, (req, res) => {
  const { notes } = req.body;
  
  db.get('SELECT * FROM letter_applications WHERE id = ?', [req.params.id], (err, app) => {
    if (err || !app) {
      return res.status(404).json({ error: 'Pengajuan tidak ditemukan' });
    }
    
    db.run(
      'UPDATE letter_applications SET status = ?, admin_notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      ['rejected', notes || null, req.params.id],
      (err) => {
        if (err) {
          return res.status(500).json({ error: 'Gagal menolak pengajuan' });
        }
        
        // Create notification for user
        db.run(
          'INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, ?, ?, ?, ?)',
          [app.user_id, 'application', 'Pengajuan Ditolak', `Pengajuan surat Anda (ID: ${app.application_id}) telah ditolak.`, '/home']
        );
        
        res.json({ success: true, message: 'Pengajuan ditolak' });
      }
    );
  });
});

app.put('/api/letter-applications/:id/custom-content', requireAuth, requireAdmin, (req, res) => {
  const { custom_content } = req.body || {};
  const trimmedContent = custom_content && typeof custom_content === 'string' ? custom_content.trim() : '';

  db.get('SELECT letter_type FROM letter_applications WHERE id = ?', [req.params.id], (err, app) => {
    if (err || !app) {
      return res.status(404).json({ error: 'Pengajuan tidak ditemukan' });
    }
    if (app.letter_type !== 'other') {
      return res.status(400).json({ error: 'Hanya pengajuan surat lainnya yang dapat diedit' });
    }

    db.run(
      'UPDATE letter_applications SET custom_letter_content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [trimmedContent || null, req.params.id],
      (updateErr) => {
        if (updateErr) {
          return res.status(500).json({ error: 'Gagal menyimpan isi surat' });
        }
        res.json({ success: true });
      }
    );
  });
});

app.get('/api/letter-applications/:id/download', requireAuth, (req, res) => {
  db.get('SELECT * FROM letter_applications WHERE id = ?', [req.params.id], (err, app) => {
    if (err || !app) {
      return res.status(404).json({ error: 'Pengajuan tidak ditemukan' });
    }
    
    // Check if user is admin or owner
    if (req.session.user.role !== 'admin' && app.user_id !== req.session.user.id) {
      return res.status(403).json({ error: 'Akses ditolak' });
    }
    
    if (!app.pdf_path || !fs.existsSync(app.pdf_path)) {
      return res.status(404).json({ error: 'File surat tidak ditemukan' });
    }
    
    res.download(app.pdf_path, `Surat-${app.application_id}.pdf`);
  });
});

// API Routes - Payments
app.post('/api/payments', requireAuth, upload.single('proof'), (req, res) => {
  const { amount, period, payment_method } = req.body;
  const userId = req.session.user.id;
  
  if (!amount || !period || !payment_method) {
    return res.status(400).json({ error: 'Semua field wajib harus diisi' });
  }
  
  if (!req.file) {
    return res.status(400).json({ error: 'Bukti pembayaran wajib diupload' });
  }
  
  db.run(
    'INSERT INTO payments (user_id, amount, period, payment_method, proof_path) VALUES (?, ?, ?, ?, ?)',
    [userId, amount, period, payment_method, req.file.path],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Gagal melakukan pembayaran' });
      }
      
      res.json({ 
        success: true, 
        message: 'Pembayaran berhasil',
        payment_id: this.lastID
      });
    }
  );
});

app.get('/api/payments/my', requireAuth, (req, res) => {
  db.all(
    'SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC',
    [req.session.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat pembayaran' });
      }
      res.json({ payments: rows });
    }
  );
});

app.get('/api/payments/:id/invoice', requireAuth, (req, res) => {
  db.get('SELECT * FROM payments WHERE id = ?', [req.params.id], (err, payment) => {
    if (err || !payment) {
      return res.status(404).json({ error: 'Pembayaran tidak ditemukan' });
    }
    
    // Check if user is admin or owner
    if (req.session.user.role !== 'admin' && payment.user_id !== req.session.user.id) {
      return res.status(403).json({ error: 'Akses ditolak' });
    }

    if (payment.status !== 'approved') {
      return res.status(400).json({ error: 'Invoice belum tersedia untuk pembayaran ini' });
    }
    
    if (!payment.invoice_path || !fs.existsSync(payment.invoice_path)) {
      return res.status(404).json({ error: 'File invoice tidak ditemukan' });
    }
    
    res.download(payment.invoice_path, `Invoice-${payment.id}.pdf`);
  });
});

app.get('/api/payments/all', requireAuth, requireAdmin, (req, res) => {
  db.all(
    `SELECT p.*, 
            u.full_name as user_name, u.nik as user_nik
     FROM payments p
     JOIN users u ON p.user_id = u.id
     ORDER BY p.created_at DESC`,
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat riwayat pembayaran' });
      }
      res.json({ payments: rows });
    }
  );
});

app.post('/api/payments/:id/approve', requireAuth, requireAdmin, (req, res) => {
  const paymentId = parseInt(req.params.id, 10);
  if (!Number.isInteger(paymentId)) {
    return res.status(400).json({ error: 'ID pembayaran tidak valid' });
  }

  db.get('SELECT * FROM payments WHERE id = ?', [paymentId], (err, payment) => {
    if (err || !payment) {
      return res.status(404).json({ error: 'Pembayaran tidak ditemukan' });
    }
    if (payment.status === 'approved') {
      return res.status(400).json({ error: 'Pembayaran sudah disetujui' });
    }

    generateInvoice(paymentId, payment.user_id, payment.amount, payment.period, payment.payment_method, (invoicePath) => {
      db.run(
        'UPDATE payments SET status = ?, status_notes = NULL, invoice_path = ? WHERE id = ?',
        ['approved', invoicePath, paymentId],
        (updateErr) => {
          if (updateErr) {
            return res.status(500).json({ error: 'Gagal memperbarui status pembayaran' });
          }

          db.run(
            'INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, ?, ?, ?, ?)',
            [payment.user_id, 'payment', 'Pembayaran Disetujui', `Pembayaran iuran periode ${payment.period} telah disetujui. Invoice siap diunduh.`, '/pembayaran-iuran'],
            () => {}
          );

          res.json({ success: true, invoice_path: invoicePath });
        }
      );
    });
  });
});

// API Routes - Financial Data (Pemasukan & Pengeluaran)
app.get('/api/financial/summary', requireAuth, (req, res) => {
  // Get total income from approved payments
  db.all(
    `SELECT 
      COALESCE(SUM(amount), 0) as total_income,
      COUNT(*) as payment_count
     FROM payments 
     WHERE status = 'approved'`,
    [],
    (err, incomeRows) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat data pemasukan' });
      }
      
      // Get total expenses
      db.all(
        `SELECT 
          COALESCE(SUM(amount), 0) as total_expenses,
          COUNT(*) as expense_count
         FROM expenses`,
        [],
        (err2, expenseRows) => {
          if (err2) {
            return res.status(500).json({ error: 'Gagal memuat data pengeluaran' });
          }
          
          const income = parseFloat(incomeRows[0]?.total_income || 0);
          const expenses = parseFloat(expenseRows[0]?.total_expenses || 0);
          const balance = income - expenses;
          
          res.json({
            income: income,
            expenses: expenses,
            balance: balance,
            payment_count: incomeRows[0]?.payment_count || 0,
            expense_count: expenseRows[0]?.expense_count || 0
          });
        }
      );
    }
  );
});

// Get financial data by month for chart
app.get('/api/financial/chart', requireAuth, (req, res) => {
  const months = req.query.months || 6; // Default 6 months
  
  // Get income by month
  db.all(
    `SELECT 
      DATE_FORMAT(created_at, '%Y-%m') as month,
      COALESCE(SUM(amount), 0) as income
     FROM payments 
     WHERE status = 'approved' 
       AND created_at >= DATE_SUB(NOW(), INTERVAL ? MONTH)
     GROUP BY DATE_FORMAT(created_at, '%Y-%m')
     ORDER BY month ASC`,
    [months],
    (err, incomeRows) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat data pemasukan' });
      }
      
      // Get expenses by month
      db.all(
        `SELECT 
          DATE_FORMAT(created_at, '%Y-%m') as month,
          COALESCE(SUM(amount), 0) as expenses
         FROM expenses 
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? MONTH)
         GROUP BY DATE_FORMAT(created_at, '%Y-%m')
         ORDER BY month ASC`,
        [months],
        (err2, expenseRows) => {
          if (err2) {
            return res.status(500).json({ error: 'Gagal memuat data pengeluaran' });
          }
          
          res.json({
            income: incomeRows,
            expenses: expenseRows
          });
        }
      );
    }
  );
});

// API Routes - Expenses (Pengeluaran Kas)
app.get('/api/expenses', requireAuth, (req, res) => {
  db.all(
    `SELECT e.*, u.full_name as created_by_name
     FROM expenses e
     LEFT JOIN users u ON e.created_by = u.id
     ORDER BY e.created_at DESC
     LIMIT 100`,
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat data pengeluaran' });
      }
      res.json({ expenses: rows });
    }
  );
});

app.post('/api/expenses', requireAuth, requireAdmin, (req, res) => {
  const { amount, description, category } = req.body;
  
  if (!amount || !description) {
    return res.status(400).json({ error: 'Nominal dan keterangan wajib diisi' });
  }
  
  const amountNum = parseFloat(amount);
  if (isNaN(amountNum) || amountNum <= 0) {
    return res.status(400).json({ error: 'Nominal tidak valid' });
  }
  
  db.run(
    'INSERT INTO expenses (amount, description, category, created_by) VALUES (?, ?, ?, ?)',
    [amountNum, description, category || null, req.session.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Gagal menambahkan pengeluaran' });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.put('/api/expenses/:id', requireAuth, requireAdmin, (req, res) => {
  const expenseId = parseInt(req.params.id, 10);
  const { amount, description, category } = req.body;
  
  if (!Number.isInteger(expenseId)) {
    return res.status(400).json({ error: 'ID pengeluaran tidak valid' });
  }
  
  if (!amount || !description) {
    return res.status(400).json({ error: 'Nominal dan keterangan wajib diisi' });
  }
  
  const amountNum = parseFloat(amount);
  if (isNaN(amountNum) || amountNum <= 0) {
    return res.status(400).json({ error: 'Nominal tidak valid' });
  }
  
  db.run(
    'UPDATE expenses SET amount = ?, description = ?, category = ? WHERE id = ?',
    [amountNum, description, category || null, expenseId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Gagal memperbarui pengeluaran' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Pengeluaran tidak ditemukan' });
      }
      res.json({ success: true });
    }
  );
});

app.delete('/api/expenses/:id', requireAuth, requireAdmin, (req, res) => {
  const expenseId = parseInt(req.params.id, 10);
  
  if (!Number.isInteger(expenseId)) {
    return res.status(400).json({ error: 'ID pengeluaran tidak valid' });
  }
  
  db.run(
    'DELETE FROM expenses WHERE id = ?',
    [expenseId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Gagal menghapus pengeluaran' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Pengeluaran tidak ditemukan' });
      }
      res.json({ success: true });
    }
  );
});

app.post('/api/payments/:id/reject', requireAuth, requireAdmin, (req, res) => {
  const paymentId = parseInt(req.params.id, 10);
  const { reason } = req.body || {};
  if (!Number.isInteger(paymentId)) {
    return res.status(400).json({ error: 'ID pembayaran tidak valid' });
  }

  db.get('SELECT * FROM payments WHERE id = ?', [paymentId], (err, payment) => {
    if (err || !payment) {
      return res.status(404).json({ error: 'Pembayaran tidak ditemukan' });
    }
    if (payment.status === 'rejected') {
      return res.status(400).json({ error: 'Pembayaran sudah ditolak' });
    }

    db.run(
      'UPDATE payments SET status = ?, status_notes = ?, invoice_path = NULL WHERE id = ?',
      ['rejected', reason || null, paymentId],
      (updateErr) => {
        if (updateErr) {
          return res.status(500).json({ error: 'Gagal memperbarui status pembayaran' });
        }

        db.run(
          'INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, ?, ?, ?, ?)',
          [payment.user_id, 'payment', 'Pembayaran Ditolak', `Pembayaran iuran periode ${payment.period} ditolak.${reason ? ` Alasan: ${reason}` : ''}`, '/pembayaran-iuran'],
          () => {}
        );

        res.json({ success: true });
      }
    );
  });
});

// API Routes - Notifications
app.get('/api/notifications', requireAuth, (req, res) => {
  db.all(
    'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
    [req.session.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memuat notifikasi' });
      }
      res.json({ notifications: rows });
    }
  );
});

app.post('/api/notifications/:id/read', requireAuth, (req, res) => {
  db.run(
    'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
    [req.params.id, req.session.user.id],
    (err) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memperbarui notifikasi' });
      }
      res.json({ success: true });
    }
  );
});

// API Routes - User
app.get('/api/user/:id', requireAuth, (req, res) => {
  const userId = parseInt(req.params.id);
  
  // Check if user is admin or requesting own data
  if (req.session.user.role !== 'admin' && req.session.user.id !== userId) {
    return res.status(403).json({ error: 'Akses ditolak' });
  }
  
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal memuat data pengguna' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Pengguna tidak ditemukan' });
    }
    // Remove password from response
    delete row.password;
    res.json({ user: row });
  });
});

// Admin user management
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  db.all(`SELECT id, nik, email, phone, full_name, place_of_birth, date_of_birth, gender, 
                 address, rt, rw, kelurahan, kecamatan, city, province, postal_code, role, created_at
          FROM users
          ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal memuat daftar pengguna' });
    }
    res.json({ users: rows });
  });
});

app.put('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ error: 'ID pengguna tidak valid' });
  }

  const {
    full_name, email, phone, place_of_birth, date_of_birth,
    gender, address, rt, rw, kelurahan, kecamatan,
    city, province, postal_code, role
  } = req.body;

  if (!full_name || !email || !phone || !place_of_birth || !date_of_birth || !gender || !address) {
    return res.status(400).json({ error: 'Semua field wajib diisi' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Format email tidak valid' });
  }

  if (!/^(\+62|62|0)[0-9]{9,12}$/.test(phone)) {
    return res.status(400).json({ error: 'Format nomor telepon tidak valid' });
  }

  if (!['laki-laki', 'perempuan'].includes(gender)) {
    return res.status(400).json({ error: 'Jenis kelamin tidak valid' });
  }

  const normalizedRole = role && ['admin', 'user'].includes(role) ? role : undefined;

  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, existing) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal memuat data pengguna' });
    }
    if (!existing) {
      return res.status(404).json({ error: 'Pengguna tidak ditemukan' });
    }

    db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email.trim(), userId], (err, emailRow) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal memeriksa email' });
      }
      if (emailRow) {
        return res.status(400).json({ error: 'Email sudah digunakan pengguna lain' });
      }

      db.get('SELECT id FROM users WHERE phone = ? AND id != ?', [phone.trim(), userId], (err, phoneRow) => {
        if (err) {
          return res.status(500).json({ error: 'Gagal memeriksa nomor telepon' });
        }
        if (phoneRow) {
          return res.status(400).json({ error: 'Nomor telepon sudah digunakan pengguna lain' });
        }

        const applyUpdate = () => {
          db.run(`UPDATE users 
                  SET full_name = ?, email = ?, phone = ?, place_of_birth = ?, date_of_birth = ?, 
                      gender = ?, address = ?, rt = ?, rw = ?, kelurahan = ?, kecamatan = ?, 
                      city = ?, province = ?, postal_code = ?, role = ? 
                  WHERE id = ?`,
            [
              full_name.trim(),
              email.trim(),
              phone.trim(),
              place_of_birth.trim(),
              date_of_birth,
              gender,
              address.trim(),
              rt || null,
              rw || null,
              kelurahan || null,
              kecamatan || null,
              city || null,
              province || null,
              postal_code || null,
              normalizedRole || existing.role,
              userId
            ],
            function(err) {
              if (err) {
                return res.status(500).json({ error: 'Gagal memperbarui pengguna' });
              }
              res.json({ success: true });
            }
          );
        };

        if (existing.role === 'admin' && normalizedRole === 'user') {
          db.get('SELECT COUNT(*) as total FROM users WHERE role = ?', ['admin'], (err, row) => {
            if (err) {
              return res.status(500).json({ error: 'Gagal memeriksa jumlah admin' });
            }
            if (row.total <= 1) {
              return res.status(400).json({ error: 'Tidak dapat mengubah role admin terakhir' });
            }
            applyUpdate();
          });
        } else {
          applyUpdate();
        }
      });
    });
  });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ error: 'ID pengguna tidak valid' });
  }

  if (userId === req.session.user.id) {
    return res.status(400).json({ error: 'Anda tidak dapat menghapus akun sendiri' });
  }

  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal memuat data pengguna' });
    }
    if (!user) {
      return res.status(404).json({ error: 'Pengguna tidak ditemukan' });
    }

    const proceedDeletion = () => {
      db.run('DELETE FROM letter_applications WHERE user_id = ?', [userId], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Gagal menghapus pengajuan pengguna' });
        }
        db.run('DELETE FROM payments WHERE user_id = ?', [userId], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Gagal menghapus pembayaran pengguna' });
          }
          db.run('DELETE FROM notifications WHERE user_id = ?', [userId], (err) => {
            if (err) {
              return res.status(500).json({ error: 'Gagal menghapus notifikasi pengguna' });
            }
            db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
              if (err) {
                return res.status(500).json({ error: 'Gagal menghapus pengguna' });
              }
              res.json({ success: true });
            });
          });
        });
      });
    };

    if (user.role === 'admin') {
      db.get('SELECT COUNT(*) as total FROM users WHERE role = ?', ['admin'], (err, row) => {
        if (err) {
          return res.status(500).json({ error: 'Gagal memeriksa jumlah admin' });
        }
        if (row.total <= 1) {
          return res.status(400).json({ error: 'Tidak dapat menghapus admin terakhir' });
        }
        proceedDeletion();
      });
    } else {
      proceedDeletion();
    }
  });
});

// Get own profile with full details
app.get('/api/profile', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal memuat data profil' });
    }
    if (!user) {
      return res.status(404).json({ error: 'Pengguna tidak ditemukan' });
    }
    // Remove password from response
    delete user.password;
    res.json({ user });
  });
});

// Update own profile (email, phone, password)
app.put('/api/profile', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const { email, phone, current_password, new_password, confirm_password } = req.body;

  // At least one field must be provided
  if (!email && !phone && !new_password) {
    return res.status(400).json({ error: 'Minimal satu field harus diisi untuk diperbarui' });
  }

  // Validate email if provided
  if (email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Format email tidak valid' });
    }
  }

  // Validate phone if provided
  if (phone) {
    if (!/^(\+62|62|0)[0-9]{9,12}$/.test(phone)) {
      return res.status(400).json({ error: 'Format nomor telepon tidak valid' });
    }
  }

  // Validate password change
  if (new_password) {
    if (!current_password) {
      return res.status(400).json({ error: 'Password lama harus diisi untuk mengubah password' });
    }
    if (new_password.length < 6) {
      return res.status(400).json({ error: 'Password baru minimal 6 karakter' });
    }
    if (new_password !== confirm_password) {
      return res.status(400).json({ error: 'Password baru dan konfirmasi password tidak cocok' });
    }
  }

  // Get current user data
  db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal memuat data pengguna' });
    }
    if (!user) {
      return res.status(404).json({ error: 'Pengguna tidak ditemukan' });
    }

    // Verify current password if changing password
    if (new_password) {
      try {
        const match = await bcrypt.compare(current_password, user.password);
        if (!match) {
          return res.status(401).json({ error: 'Password lama tidak benar' });
        }
      } catch (error) {
        return res.status(500).json({ error: 'Gagal memverifikasi password' });
      }
    }

    // Check email uniqueness if changing email
    const emailChanged = email && email.trim() !== user.email;
    const phoneChanged = phone && phone.trim() !== user.phone;

    const checkAndUpdate = () => {
      // Check email uniqueness
      if (emailChanged) {
        db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email.trim(), userId], (err, emailRow) => {
          if (err) {
            return res.status(500).json({ error: 'Gagal memeriksa email' });
          }
          if (emailRow) {
            return res.status(400).json({ error: 'Email sudah digunakan pengguna lain' });
          }
          checkPhoneAndUpdate();
        });
        return;
      }
      checkPhoneAndUpdate();
    };

    const checkPhoneAndUpdate = () => {
      // Check phone uniqueness
      if (phoneChanged) {
        db.get('SELECT id FROM users WHERE phone = ? AND id != ?', [phone.trim(), userId], async (err, phoneRow) => {
          if (err) {
            return res.status(500).json({ error: 'Gagal memeriksa nomor telepon' });
          }
          if (phoneRow) {
            return res.status(400).json({ error: 'Nomor telepon sudah digunakan pengguna lain' });
          }
          await performUpdate();
        });
        return;
      }
      performUpdate();
    };

    const performUpdate = async () => {
      let hashedPassword = user.password;
      
      // Hash new password if provided
      if (new_password) {
        try {
          hashedPassword = await bcrypt.hash(new_password, 10);
        } catch (error) {
          return res.status(500).json({ error: 'Gagal mengenkripsi password baru' });
        }
      }

      // Build update query dynamically
      const updates = [];
      const values = [];

      if (email) {
        updates.push('email = ?');
        values.push(email.trim());
      }
      if (phone) {
        updates.push('phone = ?');
        values.push(phone.trim());
      }
      if (new_password) {
        updates.push('password = ?');
        values.push(hashedPassword);
      }

      if (updates.length === 0) {
        return res.status(400).json({ error: 'Tidak ada perubahan yang dilakukan' });
      }

      values.push(userId);

      db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values, (err) => {
        if (err) {
          return res.status(500).json({ error: 'Gagal memperbarui profil' });
        }

        // Update session if email or phone changed
        if (email) req.session.user.email = email.trim();
        if (phone) req.session.user.phone = phone.trim();

        res.json({ success: true, message: 'Profil berhasil diperbarui' });
      });
    };

    checkAndUpdate();
  });
});

function parseApplicationRow(row) {
  if (!row) return row;
  if (row.details) {
    try {
      // MySQL JSON sudah dalam format object, atau bisa string
      row.details = typeof row.details === 'string' ? JSON.parse(row.details) : row.details;
    } catch (error) {
      row.details = null;
    }
  } else {
    row.details = null;
  }
  return row;
}

// Helper function to generate letter PDF
async function generateLetterPDF(application, user, callback) {
  const doc = new PDFDocument({ margin: 50 });
  
  // Generate filename: Surat-SRT-(Nama)-(Tanggal)
  let parsedDetails = {};
  if (application.details) {
    try {
      parsedDetails = typeof application.details === 'string' ? JSON.parse(application.details) : application.details;
    } catch (error) {
      parsedDetails = {};
    }
  }
  
  // Get applicant name for filename
  let applicantName = user.full_name || 'Unknown';
  if (application.letter_type === 'mutation') {
    applicantName = parsedDetails.mutationName || user.full_name || 'Unknown';
  }
  // Sanitize name for filename (remove special characters, replace spaces with hyphens)
  const sanitizedName = applicantName.replace(/[^a-zA-Z0-9\s]/g, '').replace(/\s+/g, '-');
  
  // Get application date (use created_at if available, otherwise current date)
  const appDate = application.created_at ? new Date(application.created_at) : new Date();
  const dateStr = appDate.toISOString().slice(0, 10).replace(/-/g, ''); // Format: YYYYMMDD
  
  const filename = `Surat-SRT-${sanitizedName}-${dateStr}.pdf`;
  const filepath = path.join(__dirname, 'uploads', filename);
  
  // Ensure uploads directory exists
  if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
  }

  const stream = fs.createWriteStream(filepath);
  doc.pipe(stream);

  const formatDateIndo = (date) => new Date(date).toLocaleDateString('id-ID', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
  
  // Get application date for footer (use created_at if available, otherwise current date)
  const footerDate = application.created_at ? new Date(application.created_at) : new Date();

  const drawBarcodeSignature = (x, y, code) => {
    const sanitized = (code || '').replace(/[^A-Z0-9]/gi, '').toUpperCase() || 'TTD-DIGITAL';
    const pattern = sanitized.split('').map((c, idx) => {
      const bars = (c.charCodeAt(0) + idx) % 7 + 3; // 3-9 bars
      return '|'.repeat(bars);
    }).join(' ');

    doc.fontSize(9).font('Courier');
    doc.text('Tanda Tangan Digital (Barcode)', x, y);
    doc.rect(x, y + 12, 160, 40).stroke();
    doc.text(pattern, x + 6, y + 18, { width: 148, align: 'left' });
    doc.font('Helvetica');
  };

  if (application.letter_type === 'mutation') {
    // Template khusus mutasi sesuai permintaan
    const cityName = (user.city && user.city.trim()) || 'Bandung';
    const mutationName = parsedDetails.mutationName || user.full_name || '-';
    const mutationNik = parsedDetails.mutationNik || user.nik || '-';
    const oldAddress = parsedDetails.oldAddress || user.address || '-';
    const newAddress = parsedDetails.newAddress || '-';
    const moveDate = parsedDetails.moveDate ? formatDateIndo(parsedDetails.moveDate) : '-';
    const purpose = application.purpose || '-';

    const labelWidth = 120;
    const valueStart = doc.page.margins.left + labelWidth + 12;

    const addField = (label, value) => {
      const y = doc.y;
      doc.fontSize(12).text(label, doc.page.margins.left, y, { width: labelWidth });
      doc.text(':', doc.page.margins.left + labelWidth, y);
      doc.text(value || '-', valueStart, y, { align: 'left' });
      doc.moveDown(0.6);
    };

    doc.fontSize(12);
    doc.text(`${cityName}, ${formatDateIndo(new Date())}`);
    doc.moveDown(0.5);
    doc.fontSize(12).text('Perihal: Surat keterangan mutasi');
    doc.moveDown(1.2);
    doc.text('Dengan Hormat');
    doc.moveDown(0.8);
    doc.text('Saya yang bertanda tangan dibawah ini:');
    doc.moveDown(0.8);

    addField('Nama Lengkap', mutationName);
    addField('NIK', mutationNik);
    addField('Alamat Lama', oldAddress);

    doc.moveDown(0.8);
    doc.text('Dengan ini saya bermaksud mengajukan surat keterangan mutasi (pindah). Adapun maksud dan tujuan kepindahan ini adalah sebagai berikut:');
    doc.moveDown(0.8);

    addField('Maksud dan tujuan', purpose);
    addField('Alamat Baru', newAddress);
    addField('Tanggal Pindah', moveDate);

    doc.moveDown(1.2);
    doc.text('Demikian surat permohonan ini saya ajukan, saya sangat mengharapkan agar Bapak/Ibu dapat menyetujui surat keterangan mutasi yang saya buat ini. Atas perhatiannya, saya ucapkan terimakasih.', {
      align: 'justify'
    });
    doc.moveDown(2);

    const sigBlockWidth = 200;
    const sigX = doc.page.width - doc.page.margins.right - sigBlockWidth;
    const sigY = doc.y;

    doc.text('Hormat saya,', sigX, sigY, { width: sigBlockWidth, align: 'left' });

    // Generate QR (fallback ke barcode teks jika gagal)
    const qrData = `ID:${application.application_id};NIK:${mutationNik};NAMA:${mutationName}`;
    let qrBuffer = null;
    try {
      qrBuffer = await QRCode.toBuffer(qrData, { margin: 1, scale: 4 });
    } catch (err) {
      qrBuffer = null;
    }

    const qrTop = sigY + 14;
    if (qrBuffer) {
      doc.image(qrBuffer, sigX, qrTop, { fit: [90, 90], align: 'left' });
      doc.rect(sigX, qrTop, 90, 90).stroke();
      doc.text('Tanda Tangan Digital (QR)', sigX + 96, qrTop + 36, { width: 90, align: 'left' });
    } else {
      drawBarcodeSignature(sigX, qrTop, application.application_id);
    }

    doc.moveDown(7);
  } else if (application.letter_type === 'death') {
    // Template khusus surat kematian sesuai permintaan
    const cityName = (user.city && user.city.trim()) || 'Bandung';
    const rt = user.rt || '';
    const rw = user.rw || '';
    const kelurahan = user.kelurahan || '';
    const kecamatan = user.kecamatan || '';
    
    // Data pemohon
    const applicantName = user.full_name || '-';
    const applicantNik = user.nik || '-';
    
    // Data almarhum/almarhumah
    const deceasedName = parsedDetails.deceasedName || '-';
    const deceasedNik = parsedDetails.deceasedNik || '-';
    const deathDate = parsedDetails.deathDate ? formatDateIndo(parsedDetails.deathDate) : '-';
    const deathLocation = parsedDetails.deathLocation || '-';
    const purpose = application.purpose || '-';
    const deathNotes = parsedDetails.deathNotes || '';

    const labelWidth = 120;
    const valueStart = doc.page.margins.left + labelWidth + 12;

    const addField = (label, value) => {
      const y = doc.y;
      doc.fontSize(12).text(label, doc.page.margins.left, y, { width: labelWidth });
      doc.text(':', doc.page.margins.left + labelWidth, y);
      doc.text(value || '-', valueStart, y, { align: 'left' });
      doc.moveDown(0.6);
    };

    // Header
    doc.fontSize(16).text('SURAT KETERANGAN KEMATIAN', { align: 'center' });
    doc.moveDown(2);

    // Introduction
    doc.fontSize(12);
    let introText = 'Yang bertanda tangan di bawah ini Ketua RT';
    if (rt) introText += ` ${rt}`;
    if (rw) introText += ` RW ${rw}`;
    if (kelurahan) introText += ` kelurahan ${kelurahan}`;
    if (kecamatan) introText += ` Kecamatan ${kecamatan}`;
    if (cityName) introText += ` Kota ${cityName}`;
    introText += ' dengan ini menerangkan bahwa:';
    
    doc.text(introText, { align: 'justify' });
    doc.moveDown(1);

    // Data pemohon
    addField('Nama Lengkap', applicantName);
    addField('NIK', applicantNik);

    doc.moveDown(1);
    doc.text('Kemudian, saya menerima permohonan surat keterangan kematian dari orang yang telah meninggal dunia pada:', { align: 'justify' });
    doc.moveDown(0.8);

    // Data almarhum/almarhumah
    addField('Nama Lengkap', deceasedName);
    addField('NIK', deceasedNik);
    addField('Tanggal Kematian', deathDate);
    addField('Lokasi Kematian', deathLocation);
    addField('Tujuan Pengajuan', purpose);
    if (deathNotes) {
      addField('Keterangan Tambahan', deathNotes);
    }

    doc.moveDown(1.5);
    doc.text('Demikian surat ini saya buat karena saya telah menyetujui pembuatan surat kematian tersebut. Atas perhatiannya saya ucapkan terimakasih.', { align: 'justify' });
    doc.moveDown(2);

    // Signature section
    const sigBlockWidth = 200;
    const sigX = doc.page.width - doc.page.margins.right - sigBlockWidth;
    const sigY = doc.y;

    doc.text(`${cityName}, ${formatDateIndo(footerDate)}`, sigX, sigY, { width: sigBlockWidth, align: 'left' });

    // Generate QR (fallback ke barcode teks jika gagal)
    const qrData = `ID:${application.application_id};NIK:${applicantNik};NAMA:${applicantName}`;
    let qrBuffer = null;
    try {
      qrBuffer = await QRCode.toBuffer(qrData, { margin: 1, scale: 4 });
    } catch (err) {
      qrBuffer = null;
    }

    const qrTop = sigY + 20;
    if (qrBuffer) {
      doc.image(qrBuffer, sigX, qrTop, { fit: [90, 90], align: 'left' });
      doc.rect(sigX, qrTop, 90, 90).stroke();
      doc.text('Tanda Tangan Digital (QR)', sigX + 96, qrTop + 36, { width: 90, align: 'left' });
    } else {
      drawBarcodeSignature(sigX, qrTop, application.application_id);
    }

    doc.moveDown(7);
  } else if (application.letter_type === 'birth') {
    // Template khusus surat kelahiran sesuai permintaan
    const cityName = (user.city && user.city.trim()) || 'Bandung';
    const rt = user.rt || '';
    const rw = user.rw || '';
    const kelurahan = user.kelurahan || '';
    const kecamatan = user.kecamatan || '';
    
    // Data pemohon
    const applicantName = user.full_name || '-';
    const applicantPlaceOfBirth = user.place_of_birth || '-';
    const applicantDateOfBirth = user.date_of_birth ? formatDateIndo(user.date_of_birth) : '-';
    const applicantGender = user.gender || '-';
    const applicantAddress = user.address || '-';
    
    // Data bayi
    const babyName = parsedDetails.babyName || '-';
    const babyBirthDate = parsedDetails.babyBirthDate ? formatDateIndo(parsedDetails.babyBirthDate) : '-';
    const babyBirthPlace = parsedDetails.babyBirthPlace || applicantPlaceOfBirth || '-';
    const parentName = parsedDetails.parentName || '-';
    const parentNik = parsedDetails.parentNik || '-';
    const babyGender = parsedDetails.babyGender || '-';
    const childNumber = parsedDetails.childNumber || '-';

    const labelWidth = 120;
    const valueStart = doc.page.margins.left + labelWidth + 12;

    const addField = (label, value) => {
      const y = doc.y;
      doc.fontSize(12).text(label, doc.page.margins.left, y, { width: labelWidth });
      doc.text(':', doc.page.margins.left + labelWidth, y);
      doc.text(value || '-', valueStart, y, { align: 'left' });
      doc.moveDown(0.6);
    };

    // Header
    doc.fontSize(16).text('SURAT KETERANGAN', { align: 'center' });
    doc.moveDown(2);

    // Introduction
    doc.fontSize(12);
    let introText = 'Yang bertanda tangan di bawah ini Ketua RT';
    if (rt) introText += ` ${rt}`;
    if (rw) introText += ` RW ${rw}`;
    if (kelurahan) introText += ` kelurahan ${kelurahan}`;
    if (kecamatan) introText += ` Kecamatan ${kecamatan}`;
    if (cityName) introText += ` Kota ${cityName}`;
    introText += ' dengan ini menerangkan bahwa :';
    
    doc.text(introText, { align: 'justify' });
    doc.moveDown(1);

    // Data pemohon (nama bayi)
    addField('Nama', babyName);
    addField('Tempat, Tgl. Lahir', `${applicantPlaceOfBirth}, ${applicantDateOfBirth}`);
    addField('Jenis Kelamin', applicantGender);
    addField('Alamat', applicantAddress);

    doc.moveDown(1);
    doc.text('Nama di atas merupakan nama anak yang telah lahir dengan data sebagai berikut :', { align: 'justify' });
    doc.moveDown(0.8);

    // Data anak
    addField('Tempat, Tgl. Lahir', `${babyBirthPlace}, ${babyBirthDate}`);
    addField('Nama Ayah Kandung', parentName);

    doc.moveDown(1.5);
    doc.text('Demikian surat keterangan kelahiran ini saya buat, karena saya telah menyetujui surat permohonan yang Bapak/Ibu buat akta kelahiran dari anak Bapak/Ibu. Atas perhatiannya saya ucapkan terimakasih.', { align: 'justify' });
    doc.moveDown(2);

    // Signature section
    const sigBlockWidth = 200;
    const sigX = doc.page.width - doc.page.margins.right - sigBlockWidth;
    const sigY = doc.y;

    doc.text(`${cityName}, ${formatDateIndo(footerDate)}`, sigX, sigY, { width: sigBlockWidth, align: 'left' });

    // Generate QR (fallback ke barcode teks jika gagal)
    const qrData = `ID:${application.application_id};NIK:${user.nik};NAMA:${applicantName}`;
    let qrBuffer = null;
    try {
      qrBuffer = await QRCode.toBuffer(qrData, { margin: 1, scale: 4 });
    } catch (err) {
      qrBuffer = null;
    }

    const qrTop = sigY + 20;
    if (qrBuffer) {
      doc.image(qrBuffer, sigX, qrTop, { fit: [90, 90], align: 'left' });
      doc.rect(sigX, qrTop, 90, 90).stroke();
      doc.text('Tanda Tangan Digital (QR)', sigX + 96, qrTop + 36, { width: 90, align: 'left' });
    } else {
      drawBarcodeSignature(sigX, qrTop, application.application_id);
    }

    doc.moveDown(7);
  } else if (application.letter_type === 'other') {
    // Template khusus surat lainnya sesuai permintaan
    const cityName = (user.city && user.city.trim()) || 'Bandung';
    const rt = user.rt || '';
    const rw = user.rw || '';
    const kelurahan = user.kelurahan || '';
    const kecamatan = user.kecamatan || '';
    
    // Data pemohon
    const applicantName = user.full_name || '-';
    const applicantNik = user.nik || '-';
    const applicantPlaceOfBirth = user.place_of_birth || '-';
    const applicantDateOfBirth = user.date_of_birth ? formatDateIndo(user.date_of_birth) : '-';
    const applicantGender = user.gender || '-';
    const applicantAddress = user.address || '-';
    const purpose = application.purpose || '-';
    const customContent = application.custom_letter_content && application.custom_letter_content.trim();

    const labelWidth = 120;
    const valueStart = doc.page.margins.left + labelWidth + 12;

    const addField = (label, value) => {
      const y = doc.y;
      doc.fontSize(12).text(label, doc.page.margins.left, y, { width: labelWidth });
      doc.text(':', doc.page.margins.left + labelWidth, y);
      doc.text(value || '-', valueStart, y, { align: 'left' });
      doc.moveDown(0.6);
    };

    // Header - tanggal dan kota di kanan atas
    doc.fontSize(12);
    const headerY = doc.page.margins.top;
    doc.text(`${cityName}, ${formatDateIndo(footerDate)}`, doc.page.width - doc.page.margins.right - 200, headerY, { align: 'right', width: 200 });
    
    // Lampiran dan Hal di kiri atas
    doc.text('Lamp : -', doc.page.margins.left, headerY);
    doc.text('Hal : Surat Keterangan', doc.page.margins.left, headerY + 15);
    
    // Set posisi untuk konten berikutnya
    doc.y = headerY + 40;

    // Introduction
    let introText = 'Yang bertanda tangan dibawah ini Ketua RT';
    if (rt) introText += ` ${rt}`;
    if (rw) introText += ` RW ${rw}`;
    if (kelurahan) introText += ` Kelurahan ${kelurahan}`;
    if (kecamatan) introText += ` Kecamatan ${kecamatan}`;
    if (cityName) introText += ` kota ${cityName}`;
    introText += ' dengan ini menerangkan bahwa :';
    
    doc.text(introText, { align: 'justify' });
    doc.moveDown(1);

    // Data pemohon
    addField('NIK', applicantNik);
    addField('Nama Lengkap', applicantName);
    addField('Tempat, Tanggal Lahir', `${applicantPlaceOfBirth}, ${applicantDateOfBirth}`);
    addField('Jenis Kelamin', applicantGender);
    addField('Alamat', applicantAddress);
    addField('Tujuan Pengajuan', purpose);

    doc.moveDown(1.5);
    
    // Content - gunakan custom content jika ada, jika tidak gunakan penutup standar
    if (customContent) {
      doc.text(customContent, { align: 'justify' });
    } else {
      doc.text('Demikian surat keterangan ini saya buat, karena saya telah menyetujui permohonan surat yang Bapak/ibu ajukan. Atas perhatiannya kami ucapkan terimakasih.', { align: 'justify' });
    }
    
    doc.moveDown(2);

    // Signature section
    const sigBlockWidth = 200;
    const sigX = doc.page.width - doc.page.margins.right - sigBlockWidth;
    const sigY = doc.y;

    doc.text('Hormat Saya,', sigX, sigY, { width: sigBlockWidth, align: 'left' });

    // Generate QR (fallback ke barcode teks jika gagal)
    const qrData = `ID:${application.application_id};NIK:${applicantNik};NAMA:${applicantName}`;
    let qrBuffer = null;
    try {
      qrBuffer = await QRCode.toBuffer(qrData, { margin: 1, scale: 4 });
    } catch (err) {
      qrBuffer = null;
    }

    const qrTop = sigY + 20;
    if (qrBuffer) {
      doc.image(qrBuffer, sigX, qrTop, { fit: [90, 90], align: 'left' });
      doc.rect(sigX, qrTop, 90, 90).stroke();
      doc.text('Tanda Tangan Digital (QR)', sigX + 96, qrTop + 36, { width: 90, align: 'left' });
    } else {
      drawBarcodeSignature(sigX, qrTop, application.application_id);
    }

    doc.moveDown(7);
  } else {
    // Default template untuk mutation (jika masih ada)
    // Header
    doc.fontSize(16).text('SURAT KETERANGAN', { align: 'center' });
    doc.moveDown();

    const letterTypeNames = {
      'mutation': 'SURAT LAPORAN MUTASI'
    };

    doc.fontSize(14).text(letterTypeNames[application.letter_type] || 'SURAT KETERANGAN', { align: 'center' });
    doc.moveDown(2);

    // Content
    doc.fontSize(12);
    doc.text(`Yang bertanda tangan di bawah ini, Ketua RT, menerangkan bahwa:`, { align: 'justify' });
    doc.moveDown();

    doc.text(`Nama                : ${user.full_name || '-'}`);
    doc.text(`NIK                 : ${user.nik || '-'}`);
    doc.text(`Tempat/Tgl Lahir    : ${user.place_of_birth || '-'}, ${user.date_of_birth || '-'}`);
    doc.text(`Jenis Kelamin       : ${user.gender || '-'}`);
    doc.text(`Alamat              : ${user.address || '-'}`);
    if (user.rt) doc.text(`RT/RW              : ${user.rt}/${user.rw || '-'}`);
    if (user.kelurahan) doc.text(`Kelurahan          : ${user.kelurahan || '-'}`);
    if (user.kecamatan) doc.text(`Kecamatan          : ${user.kecamatan || '-'}`);
    if (user.city) doc.text(`Kota/Kabupaten     : ${user.city || '-'}`);
    if (user.province) doc.text(`Provinsi           : ${user.province || '-'}`);

    const details = parsedDetails;
    const fallbackDescription = details.otherDescription || application.purpose || '-';

    doc.moveDown();
    doc.text(`Tujuan Pengajuan: ${fallbackDescription}`, { align: 'justify' });
    doc.moveDown(2);

    doc.text(`Demikian surat keterangan ini dibuat dengan sebenar-benarnya untuk dapat dipergunakan sebagaimana mestinya.`, { align: 'justify' });
    doc.moveDown(3);

    // Signature section
    doc.text('Ketua RT', { align: 'right' });
    doc.moveDown(3);
    doc.text('___________________', { align: 'right' });

    // Add electronic signature text
    doc.fontSize(10).text('Tanda Tangan Elektronik', { align: 'right' });
  }

  // Footer
  doc.fontSize(10);
  doc.text(`ID Pengajuan: ${application.application_id}`, { align: 'center' });
  doc.text(`Tanggal: ${formatDateIndo(footerDate)}`, { align: 'center' });

  stream.on('finish', () => {
    callback(filepath);
  });

  doc.end();
}

// Helper function to generate invoice PDF
function generateInvoice(paymentId, userId, amount, period, paymentMethod, callback) {
  // Get user data first
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user) {
      return callback(null);
    }

    const doc = new PDFDocument({ margin: 50 });
    const filename = `invoice-${paymentId}.pdf`;
    const filepath = path.join(__dirname, 'uploads', filename);
    
    // Ensure uploads directory exists
    if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
      fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
    }
    
    const stream = fs.createWriteStream(filepath);
    doc.pipe(stream);
    
    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;
    const margin = doc.page.margins.left;
    const rightMargin = doc.page.margins.right;
    
    // Header - horizontal line on left, INVOICE on right
    const headerY = 50;
    doc.moveTo(margin, headerY)
       .lineTo(pageWidth / 2, headerY)
       .stroke();
    
    doc.fontSize(48)
       .fillColor('#888888')
       .text('INVOICE', pageWidth - rightMargin - 200, headerY - 20, { align: 'right', width: 200 });
    
    doc.fillColor('black');
    doc.moveDown(3);
    
    // Left side - Recipient information
    const leftX = margin;
    const rightX = pageWidth - rightMargin - 200;
    let currentY = doc.y;
    
    doc.fontSize(10)
       .text('ISSUED TO:', leftX, currentY);
    currentY += 20;
    
    doc.fontSize(12)
       .text(user.full_name || '-', leftX, currentY);
    currentY += 15;
    doc.fontSize(10)
       .text(user.address || '-', leftX, currentY);
    currentY += 15;
    if (user.rt && user.rw) {
      doc.text(`RT ${user.rt}/RW ${user.rw}`, leftX, currentY);
      currentY += 15;
    }
    if (user.kelurahan) {
      doc.text(user.kelurahan, leftX, currentY);
      currentY += 15;
    }
    if (user.city) {
      doc.text(user.city, leftX, currentY);
    }
    
    currentY = doc.y + 40;
    doc.fontSize(10)
       .text('PAY TO:', leftX, currentY);
    currentY += 20;
    doc.fontSize(12)
       .text('Ketua RT', leftX, currentY);
    if (user.rt) {
      doc.text(`RT ${user.rt}`, leftX, currentY + 15);
    }
    
    // Right side - Invoice details
    currentY = doc.y;
    doc.fontSize(10)
       .text('INVOICE NO:', rightX, currentY, { align: 'right', width: 200 });
    currentY += 15;
    doc.fontSize(12)
       .text(`INV-${paymentId}`, rightX, currentY, { align: 'right', width: 200 });
    currentY += 20;
    doc.fontSize(10)
       .text('DATE:', rightX, currentY, { align: 'right', width: 200 });
    currentY += 15;
    doc.fontSize(12)
       .text(new Date().toLocaleDateString('id-ID'), rightX, currentY, { align: 'right', width: 200 });
    
    // Table header
    doc.y = Math.max(doc.y, currentY) + 40;
    const tableTop = doc.y;
    const tableLeft = margin;
    const tableRight = pageWidth - rightMargin;
    const tableWidth = tableRight - tableLeft;
    
    // Table header - draw line first
    doc.moveTo(tableLeft, tableTop)
       .lineTo(tableRight, tableTop)
       .stroke();
    
    // Column widths
    const descWidth = tableWidth * 0.5;
    const unitPriceWidth = tableWidth * 0.2;
    const qtyWidth = tableWidth * 0.15;
    const totalWidth = tableWidth * 0.15;
    
    // Header text
    doc.y = tableTop + 10;
    doc.fontSize(10)
       .fillColor('#333333')
       .text('DESCRIPTION', tableLeft, doc.y, { width: descWidth })
       .text('UNIT PRICE', tableLeft + descWidth, doc.y, { width: unitPriceWidth, align: 'center' })
       .text('QTY', tableLeft + descWidth + unitPriceWidth, doc.y, { width: qtyWidth, align: 'center' })
       .text('TOTAL', tableLeft + descWidth + unitPriceWidth + qtyWidth, doc.y, { width: totalWidth, align: 'right' });
    
    // Line below header
    doc.y += 15;
    doc.fillColor('black')
       .moveTo(tableLeft, doc.y)
       .lineTo(tableRight, doc.y)
       .stroke();
    
    // Table row
    doc.y += 10;
    const description = `Iuran Kas RT - Periode ${period}`;
    const unitPrice = amount;
    const qty = 1;
    const total = amount;
    
    doc.fontSize(11)
       .text(description, tableLeft, doc.y, { width: descWidth })
       .text(`Rp ${new Intl.NumberFormat('id-ID').format(unitPrice)}`, tableLeft + descWidth, doc.y, { width: unitPriceWidth, align: 'center' })
       .text(qty.toString(), tableLeft + descWidth + unitPriceWidth, doc.y, { width: qtyWidth, align: 'center' })
       .text(`Rp ${new Intl.NumberFormat('id-ID').format(total)}`, tableLeft + descWidth + unitPriceWidth + qtyWidth, doc.y, { width: totalWidth, align: 'right' });
    
    // Summary section - move down after item
    doc.y += 30;
    const summaryY = doc.y;
    
    // SUBTOTAL - text on left, value aligned with TOTAL column
    doc.fontSize(10)
       .fillColor('#333333')
       .text('SUBTOTAL', tableLeft, summaryY);
    const totalColumnX = tableLeft + descWidth + unitPriceWidth + qtyWidth;
    doc.text(`Rp ${new Intl.NumberFormat('id-ID').format(amount)}`, totalColumnX, summaryY, { width: totalWidth, align: 'right' });
    
    // Horizontal line below subtotal
    doc.y = summaryY + 15;
    doc.fillColor('black')
       .moveTo(tableLeft, doc.y)
       .lineTo(tableRight, doc.y)
       .stroke();
    
    // TOTAL - text and value on right, aligned with TOTAL column
    doc.y += 20;
    doc.fontSize(12)
       .fillColor('#333333')
       .text('TOTAL', totalColumnX, doc.y, { width: totalWidth, align: 'right' });
    
    // Total value below TOTAL text
    doc.y += 15;
    doc.fontSize(12)
       .fillColor('black')
       .text(`Rp ${new Intl.NumberFormat('id-ID').format(amount)}`, totalColumnX, doc.y, { width: totalWidth, align: 'right' });
    
    stream.on('finish', () => {
      callback(filepath);
    });
    
    doc.end();
  });
}

