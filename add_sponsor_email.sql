-- Add sponsor_email column to cg_guest_users table
USE cg_guest;

-- Add sponsor_email column after sponsor column
ALTER TABLE cg_guest_users 
ADD COLUMN sponsor_email VARCHAR(255) DEFAULT NULL AFTER sponsor;