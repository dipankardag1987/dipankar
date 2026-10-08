require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static("public"));

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

// ==============================
// AUTH HELPERS
// ==============================

function getToken(req) {
  const auth = req.headers.authorization || "";

  if (auth.startsWith("Bearer ")) {
    return auth.substring(7);
  }

  return req.query.token || null;
}

function auth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    req.user = jwt.verify(token, process.env.JWT_SECRET);

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "ADMIN") {
    return res.status(403).json({
      error: "Admin access required",
    });
  }

  next();
}

// ==============================
// HEALTH
// ==============================

app.get("/api/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS time");

    res.json({
      success: true,
      message: "PostgreSQL connection successful",
      database: process.env.DB_NAME,
      time: result.rows[0].time,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==============================
// LOGIN
// ==============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      `SELECT id, name, email, password_hash, role, status
       FROM users
       WHERE LOWER(email) = LOWER($1)`,
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    const user = result.rows[0];

    if (user.status !== "APPROVED") {
      return res.status(403).json({
        error: `Account status: ${user.status}`,
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
      },
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed",
    });
  }
});

// ==============================
// USER REGISTRATION
// ==============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters",
      });
    }

    const exists = await pool.query(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1)",
      [email]
    );

    if (exists.rows.length) {
      return res.status(400).json({
        error: "Email already registered",
      });
    }

    const hash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users
       (name, email, password_hash, role, status)
       VALUES ($1, $2, $3, 'USER', 'PENDING')`,
      [name, email, hash]
    );

    res.json({
      message: "Registration successful. Admin approval required.",
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed",
    });
  }
});

// ==============================
// PRODUCTS
// ==============================

app.get("/api/products", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        p.id,
        p.name,
        p.sku,
        p.unit,
        p.opening_stock
        + COALESCE((
            SELECT SUM(si.quantity)
            FROM stock_in si
            WHERE si.product_id = p.id
          ), 0)
        - COALESCE((
            SELECT SUM(oi.quantity)
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE oi.product_id = p.id
              AND o.status = 'ISSUED'
          ), 0)
        AS current_stock
      FROM products p
      ORDER BY p.id DESC
    `);

    res.json(result.rows);

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load products",
    });
  }
});

// ==============================
// ADD PRODUCT
// ==============================

app.post("/api/products", auth, adminOnly, async (req, res) => {
  try {
    const { name, sku, unit = "pcs" } = req.body;

    if (!name || !sku) {
      return res.status(400).json({
        error: "Product name and SKU required",
      });
    }

    const result = await pool.query(
      `INSERT INTO products
       (name, sku, unit, opening_stock)
       VALUES ($1, $2, $3, 0)
       RETURNING *`,
      [name, sku, unit]
    );

    await audit(
      req.user.id,
      "PRODUCT_CREATED",
      `Product ${name} (${sku}) created`
    );

    res.json(result.rows[0]);

  } catch (error) {
    console.error(error);

    res.status(400).json({
      error: error.message,
    });
  }
});

// ==============================
// STOCK IN
// ==============================

app.post("/api/stock-in", auth, adminOnly, async (req, res) => {
  try {
    const { product_id, quantity } = req.body;

    if (!product_id || !quantity || Number(quantity) <= 0) {
      return res.status(400).json({
        error: "Valid product and quantity required",
      });
    }

    await pool.query(
      `INSERT INTO stock_in
       (product_id, quantity, created_by)
       VALUES ($1, $2, $3)`,
      [product_id, quantity, req.user.id]
    );

    await audit(
      req.user.id,
      "STOCK_IN",
      `Product ${product_id}, quantity ${quantity}`
    );

    res.json({
      message: "Stock added successfully",
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Stock In failed",
    });
  }
});

// ==============================
// CREATE ORDER
// ==============================

app.post("/api/orders", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const { customer_name, items } = req.body;

    if (!Array.isArray(items) || !items.length) {
      return res.status(400).json({
        error: "At least one item required",
      });
    }

    await client.query("BEGIN");

    const orderResult = await client.query(
      `INSERT INTO orders
       (user_id, customer_name, status)
       VALUES ($1, $2, 'PENDING')
       RETURNING id`,
      [
        req.user.id,
        customer_name || "Walk-in",
      ]
    );

    const orderId = orderResult.rows[0].id;

    for (const item of items) {

      if (!item.product_id || !item.quantity) {
        throw new Error("Invalid order item");
      }

      const stockResult = await client.query(
        `
        SELECT
          p.id,
          p.name,
          (
            p.opening_stock
            + COALESCE((
                SELECT SUM(si.quantity)
                FROM stock_in si
                WHERE si.product_id = p.id
              ), 0)
            - COALESCE((
                SELECT SUM(oi.quantity)
                FROM order_items oi
                JOIN orders o ON o.id = oi.order_id
                WHERE oi.product_id = p.id
                  AND o.status = 'ISSUED'
              ), 0)
          ) AS current_stock
        FROM products p
        WHERE p.id = $1
        `,
        [item.product_id]
      );

      if (!stockResult.rows.length) {
        throw new Error("Product not found");
      }

      const stock = Number(stockResult.rows[0].current_stock);
      const requested = Number(item.quantity);

      if (requested <= 0 || requested > stock) {
        throw new Error(
          `Insufficient stock for ${stockResult.rows[0].name}`
        );
      }

      await client.query(
        `INSERT INTO order_items
         (order_id, product_id, quantity, rate)
         VALUES ($1, $2, $3, $4)`,
        [
          orderId,
          item.product_id,
          requested,
          item.rate || 0,
        ]
      );
    }

    await client.query("COMMIT");

    await audit(
      req.user.id,
      "ORDER_CREATED",
      `Order #${orderId} created`
    );

    broadcast({
      type: "NEW_ORDER",
      orderId,
    });

    res.json({
      message: "Order submitted successfully",
      orderId,
    });

  } catch (error) {

    await client.query("ROLLBACK");

    console.error(error);

    res.status(400).json({
      error: error.message,
    });

  } finally {
    client.release();
  }
});

// ==============================
// ORDERS
// ==============================

app.get("/api/orders", auth, async (req, res) => {
  try {

    let query = `
      SELECT
        o.id,
        o.customer_name,
        o.status,
        o.created_at,
        u.name AS user_name
      FROM orders o
      JOIN users u ON u.id = o.user_id
    `;

    const params = [];

    if (req.user.role !== "ADMIN") {
      query += " WHERE o.user_id = $1";
      params.push(req.user.id);
    }

    query += " ORDER BY o.id DESC";

    const ordersResult = await pool.query(query, params);

    const orders = [];

    for (const order of ordersResult.rows) {

      const itemsResult = await pool.query(
        `
        SELECT
          oi.product_id,
          oi.quantity,
          oi.rate,
          p.name AS product
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = $1
        `,
        [order.id]
      );

      orders.push({
        ...order,
        items: itemsResult.rows,
      });
    }

    res.json(orders);

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load orders",
    });
  }
});

// ==============================
// APPROVE ORDER
// ==============================

app.post("/api/orders/:id/approve", auth, adminOnly, async (req, res) => {
  try {

    const result = await pool.query(
      `UPDATE orders
       SET status = 'APPROVED'
       WHERE id = $1
       AND status = 'PENDING'
       RETURNING id`,
      [req.params.id]
    );

    if (!result.rows.length) {
      return res.status(400).json({
        error: "Order cannot be approved",
      });
    }

    await audit(
      req.user.id,
      "ORDER_APPROVED",
      `Order #${req.params.id} approved`
    );

    res.json({
      message: "Order approved",
    });

  } catch (error) {
    res.status(500).json({
      error: "Approval failed",
    });
  }
});

// ==============================
// ISSUE ORDER + STOCK DEDUCTION
// ==============================

app.post("/api/orders/:id/issue", auth, adminOnly, async (req, res) => {

  const client = await pool.connect();

  try {

    await client.query("BEGIN");

    const orderResult = await client.query(
      `SELECT *
       FROM orders
       WHERE id = $1
       FOR UPDATE`,
      [req.params.id]
    );

    if (!orderResult.rows.length) {
      throw new Error("Order not found");
    }

    const order = orderResult.rows[0];

    if (order.status !== "APPROVED") {
      throw new Error("Only approved orders can be issued");
    }

    const itemsResult = await client.query(
      `
      SELECT
        oi.product_id,
        oi.quantity,
        p.name,
        (
          p.opening_stock
          + COALESCE((
              SELECT SUM(si.quantity)
              FROM stock_in si
              WHERE si.product_id = p.id
            ), 0)
          - COALESCE((
              SELECT SUM(oi2.quantity)
              FROM order_items oi2
              JOIN orders o2 ON o2.id = oi2.order_id
              WHERE oi2.product_id = p.id
                AND o2.status = 'ISSUED'
            ), 0)
        ) AS current_stock
      FROM order_items oi
      JOIN products p ON p.id = oi.product_id
      WHERE oi.order_id = $1
      `,
      [req.params.id]
    );

    for (const item of itemsResult.rows) {

      if (Number(item.quantity) > Number(item.current_stock)) {
        throw new Error(
          `Insufficient stock for ${item.name}`
        );
      }
    }

    await client.query(
      `UPDATE orders
       SET status = 'ISSUED'
       WHERE id = $1`,
      [req.params.id]
    );

    await client.query("COMMIT");

    await audit(
      req.user.id,
      "ORDER_ISSUED",
      `Order #${req.params.id} issued and stock deducted`
    );

    res.json({
      message: "Order issued and stock deducted",
    });

  } catch (error) {

    await client.query("ROLLBACK");

    res.status(400).json({
      error: error.message,
    });

  } finally {
    client.release();
  }
});

// ==============================
// PENDING USERS
// ==============================

app.get("/api/users/pending", auth, adminOnly, async (req, res) => {

  const result = await pool.query(
    `SELECT id, name, email, created_at
     FROM users
     WHERE status = 'PENDING'
     ORDER BY created_at DESC`
  );

  res.json(result.rows);
});

// ==============================
// APPROVE USER
// ==============================

app.post("/api/users/:id/approve", auth, adminOnly, async (req, res) => {

  const result = await pool.query(
    `UPDATE users
     SET status = 'APPROVED'
     WHERE id = $1
     AND status = 'PENDING'
     RETURNING id`,
    [req.params.id]
  );

  if (!result.rows.length) {
    return res.status(400).json({
      error: "User cannot be approved",
    });
  }

  await audit(
    req.user.id,
    "USER_APPROVED",
    `User #${req.params.id} approved`
  );

  res.json({
    message: "User approved",
  });
});

// ==============================
// AUDIT LOG
// ==============================

async function audit(userId, action, details) {

  try {

    await pool.query(
      `INSERT INTO audit_log
       (user_id, action, details)
       VALUES ($1, $2, $3)`,
      [userId, action, details]
    );

  } catch (error) {
    console.error("Audit error:", error.message);
  }
}

app.get("/api/audit", auth, adminOnly, async (req, res) => {

  const result = await pool.query(
    `
    SELECT
      a.id,
      a.action,
      a.details,
      a.created_at,
      u.email
    FROM audit_log a
    LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.id DESC
    LIMIT 500
    `
  );

  res.json(result.rows);
});

// ==============================
// REAL-TIME ADMIN EVENTS
// ==============================

const clients = new Set();

app.get("/api/events", auth, adminOnly, (req, res) => {

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  res.write(`data: ${JSON.stringify({
    type: "CONNECTED"
  })}\n\n`);

  clients.add(res);

  req.on("close", () => {
    clients.delete(res);
  });
});

function broadcast(data) {

  const message =
    `data: ${JSON.stringify(data)}\n\n`;

  for (const client of clients) {
    try {
      client.write(message);
    } catch (error) {
      clients.delete(client);
    }
  }
}

// ==============================
// START SERVER
// ==============================

app.listen(PORT, () => {

  console.log("");
  console.log("=================================");
  console.log(" Stock Management System");
  console.log("=================================");
  console.log(`Server: http://localhost:${PORT}`);
  console.log("PostgreSQL: Connected");
  console.log("=================================");

});