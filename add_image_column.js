// Script untuk menambahkan kolom image_path ke tabel news
// Jalankan dengan: node add_image_column.js

const db = require('./db-config');

(async () => {
  try {
    console.log('🔄 Connecting to database...');
    await db.initialize();
    
    console.log('🔄 Checking for image_path column...');
    const pool = require('mysql2/promise').createPool({
      host: 'localhost',
      user: 'root',
      password: '',
      database: 'sistem_informasi_rt'
    });
    
    const [columns] = await pool.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = 'sistem_informasi_rt' AND TABLE_NAME = 'news' AND COLUMN_NAME = 'image_path'
    `);
    
    if (columns.length === 0) {
      console.log('🔄 Adding image_path column to news table...');
      await pool.query('ALTER TABLE news ADD COLUMN image_path VARCHAR(500) NULL AFTER content');
      console.log('✅ image_path column added successfully!');
    } else {
      console.log('✅ image_path column already exists');
    }
    
    await pool.end();
    await db.close();
    console.log('✅ Migration completed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    process.exit(1);
  }
})();

