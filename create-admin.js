require("dotenv").config();

const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

async function createAdmin() {
  try {
    const name = "Administrator";
    const email = "admin@example.com";
    const password = "admin123";

    const passwordHash = await bcrypt.hash(password, 12);

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existing.rows.length > 0) {
      console.log("Admin already exists.");
    } else {
      await pool.query(
        `INSERT INTO users
        (name, email, password_hash, role, status)
        VALUES ($1, $2, $3, 'ADMIN', 'APPROVED')`,
        [name, email, passwordHash]
      );

      console.log("Admin created successfully.");
    }

    console.log("");
    console.log("Login:");
    console.log("Email: admin@example.com");
    console.log("Password: admin123");

  } catch (error) {
    console.error("Error:", error.message);
  } finally {
    await pool.end();
  }
}

createAdmin();