-- Migration: Add image_path column to news table
-- Run this SQL command to add image support for news

ALTER TABLE news 
ADD COLUMN IF NOT EXISTS image_path VARCHAR(500) NULL AFTER content;

-- If your database doesn't support IF NOT EXISTS, use:
-- ALTER TABLE news ADD COLUMN image_path VARCHAR(500) NULL;

