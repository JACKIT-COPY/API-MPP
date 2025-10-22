const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const axios = require("axios");
const dotenv = require("dotenv");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");
const rateLimit = require("express-rate-limit");
const crypto = require('crypto');
const { env } = require("process");

// At the top, add imports
const { Server } = require('socket.io');
const xss = require('xss');  // For sanitizing user input

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || "your-secret-key";
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const upload = multer({ storage: multer.memoryStorage() });

// Rate limiting for upload endpoints
const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit to 100 requests per window
    message: "Too many upload requests, please try again later.",
});

app.use(express.json());
app.use(cors());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

// function generateSecurityCredential() {
//     const password = process.env.MPESA_INITIATOR_PASSWORD;
//     const publicKey = process.env.MPESA_PUBLIC_KEY;

//     // Validate environment variables
//     if (!password || !publicKey) {
//         console.error('Missing environment variables:', {
//             hasPassword: !!password,
//             hasPublicKey: !!publicKey
//         });
//         throw new Error('Missing MPESA_INITIATOR_PASSWORD or MPESA_PUBLIC_KEY in environment variables');
//     }

//     try {
//         // Normalize public key: ensure consistent line breaks and remove extra whitespace
//         const normalizedKey = publicKey
//             .replace(/\r\n|\r/g, '\n') // Normalize line endings
//             .replace(/\n\s+/g, '\n')   // Remove extra spaces after newlines
//             .trim();

//         // Validate PEM format
//         if (!normalizedKey.startsWith('-----BEGIN PUBLIC KEY-----') || !normalizedKey.endsWith('-----END PUBLIC KEY-----')) {
//             console.error('Invalid public key format:', {
//                 keySnippet: normalizedKey.substring(0, 50),
//                 keyLength: normalizedKey.length
//             });
//             throw new Error('Public key is not in valid PEM format');
//         }

//         // Create buffer from password
//         const buffer = Buffer.from(password);

//         // Encrypt using RSA public key
//         const encrypted = crypto.publicEncrypt({
//             key: normalizedKey,
//             padding: crypto.constants.RSA_PKCS1_PADDING
//         }, buffer);

//         const securityCredential = encrypted.toString('base64');
//         console.log('✅ Security credential generated successfully');
//         return securityCredential;
//     } catch (error) {
//         console.error('Security Credential Generation Error:', {
//             message: error.message,
//             stack: error.stack,
//             keySnippet: publicKey.substring(0, 50),
//             keyLength: publicKey.length,
//             nodeVersion: process.version
//         });
//         throw new Error(`Failed to generate security credential: ${error.message}`);
//     }
// }

// module.exports = generateSecurityCredential;

// Health check endpoint
app.get("/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");
        res.json({ status: "ok", database: "connected" });
    } catch (error) {
        console.error("Health check error:", error);
        res.status(500).json({ status: "error", database: "disconnected", details: error.message });
    }
});

// Database connection and table setup
pool.connect((err) => {
    if (err) {
        console.error("Failed to connect to Supabase:", err.message);
        return;
    }
    console.log("Connected to Supabase");

    // Create user_moderation_seq
    pool.query(`
        CREATE SEQUENCE IF NOT EXISTS user_moderation_seq
        START WITH 1
        INCREMENT BY 1
    `).then(() => console.log("User moderation sequence ready"))
      .catch(err => console.error("Error creating user_moderation_seq:", err));

// Users table with role and is_creator columns
    pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE,
            password VARCHAR(100) NOT NULL,
            moderator_id VARCHAR(50),
            moderator VARCHAR(50),
            bio TEXT,
            categories TEXT[] DEFAULT '{}',
            user_moderation_id VARCHAR(50),
            role VARCHAR(20) DEFAULT 'user',
            is_creator BOOLEAN DEFAULT FALSE
        )
    `).then(() => console.log("Users table ready"))
      .catch(err => console.error("Error creating users table:", err));

    // Add is_creator column to users if it doesn't exist
    pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS is_creator BOOLEAN DEFAULT FALSE
    `).then(() => console.log("Users table migration for is_creator complete"))
      .catch(err => console.error("Error migrating users table:", err));
      

    // Posts table with status column
    pool.query(`
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            type VARCHAR(50) NOT NULL,
            title VARCHAR(255),
            caption TEXT,
            tags TEXT[] DEFAULT '{}',
            images JSONB DEFAULT '[]',
            created_at TIMESTAMP DEFAULT NOW(),
            expires_at TIMESTAMP GENERATED ALWAYS AS (created_at + INTERVAL '20 days') STORED,
            is_draft BOOLEAN DEFAULT FALSE,
            is_premium BOOLEAN DEFAULT FALSE,
            scheduled_at TIMESTAMP,
            visibility VARCHAR(50) DEFAULT 'public',
            views INTEGER DEFAULT 0,
            video_url TEXT,
            audio_url TEXT,
            duration VARCHAR(10),
            read_time INTEGER,
            shares INTEGER DEFAULT 0,
            status VARCHAR(20) DEFAULT 'pending'
        )
    `).then(() => console.log("Posts table ready"))
      .catch(err => console.error("Error creating posts table:", err));

      // Creators Page table
pool.query(`
    CREATE TABLE IF NOT EXISTS creators_page (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        profile_image TEXT,
        bio TEXT,
        socials JSONB DEFAULT '{}',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`).then(() => console.log("Creators Page table ready"))
  .catch(err => console.error("Error creating creators_page table:", err));

// Add bio and updated_at columns to creators_page if they don't exist
pool.query(`
    ALTER TABLE creators_page
    ADD COLUMN IF NOT EXISTS bio TEXT,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
`).then(() => console.log("Creators Page table migration for bio and updated_at complete"))
  .catch(err => console.error("Error migrating creators_page table:", err));

    // Subscriptions table
    pool.query(`
        CREATE TABLE IF NOT EXISTS subscriptions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            plan VARCHAR(50) NOT NULL,
            start_date DATE NOT NULL DEFAULT CURRENT_DATE,
            end_date DATE NOT NULL,
            amount INTEGER,
            payment_method VARCHAR(50),
            mpesa_transaction_id VARCHAR(50),
            payment_status VARCHAR(20) DEFAULT 'pending',
            UNIQUE(user_id, creator_id)
        )
    `).then(() => console.log("Subscriptions table ready"))
      .catch(err => console.error("Error creating subscriptions table:", err));

    // Add payment_status column if missing
    pool.query(`
        ALTER TABLE subscriptions
        ADD COLUMN IF NOT EXISTS payment_status VARCHAR(20) DEFAULT 'pending'
    `).then(() => console.log("Subscriptions table migration for payment_status complete"))
      .catch(err => console.error("Error migrating subscriptions table:", err));

    // Likes table
    pool.query(`
        CREATE TABLE IF NOT EXISTS likes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(user_id, post_id)
        )
    `).then(() => console.log("Likes table ready"))
      .catch(err => console.error("Error creating likes table:", err));

    // Comments table
    pool.query(`
        CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )
    `).then(() => console.log("Comments table ready"))
      .catch(err => console.error("Error creating comments table:", err));

    // Bookmarks table
    pool.query(`
        CREATE TABLE IF NOT EXISTS bookmarks (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(user_id, post_id)
        )
    `).then(() => console.log("Bookmarks table ready"))
      .catch(err => console.error("Error creating bookmarks table:", err));

    // Views table
    pool.query(`
        CREATE TABLE IF NOT EXISTS views (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(user_id, post_id)
        )
    `).then(() => console.log("Views table ready"))
      .catch(err => console.error("Error creating views table:", err));

    // Reports table
    pool.query(`
        CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            reporter_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            reason VARCHAR(50) NOT NULL,
            message TEXT,
            timestamp TIMESTAMP NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE (post_id, reporter_id)
        )
    `).then(() => console.log("Reports table ready"))
      .catch(err => console.error("Error creating reports table:", err));

    // Create index for reports table
    pool.query(`
        CREATE INDEX IF NOT EXISTS idx_reports_post_id ON reports(post_id);
        CREATE INDEX IF NOT EXISTS idx_reports_reporter_id ON reports(reporter_id);
        CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
    `).then(() => console.log("Reports table indexes ready"))
      .catch(err => console.error("Error creating reports table indexes:", err));

    // Moderation Comments table
    pool.query(`
        CREATE TABLE IF NOT EXISTS moderation_comments (
            id SERIAL PRIMARY KEY,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            moderator_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )
    `).then(() => console.log("Moderation comments table ready"))
      .catch(err => console.error("Error creating moderation_comments table:", err));

      // Transactions table
    pool.query(`
        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            type VARCHAR(20) NOT NULL CHECK (type IN ('subscription', 'payout')),
            amount NUMERIC(10,2) NOT NULL,
            status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
            transaction_id VARCHAR(50),
            description TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
    `).then(() => console.log("Transactions table ready"))
      .catch(err => console.error("Error creating transactions table:", err));

    // Payout Settings table
    pool.query(`
        CREATE TABLE IF NOT EXISTS payout_settings (
            creator_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            payment_method VARCHAR(50) NOT NULL CHECK (payment_method IN ('mpesa', 'bank', 'paypal', 'stripe')),
            payout_threshold INTEGER NOT NULL DEFAULT 50,
            email_notifications BOOLEAN DEFAULT TRUE,
            mpesa_phone VARCHAR(20)
        )
    `).then(() => console.log("Payout Settings table ready"))
      .catch(err => console.error("Error creating payout_settings table:", err));

      // Create subscription_tiers table
         pool.query(`
            CREATE TABLE IF NOT EXISTS subscription_tiers (
                id SERIAL PRIMARY KEY,
                creator_id INTEGER NOT NULL REFERENCES creators_page(user_id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                price INTEGER NOT NULL CHECK (price >= 0),
                interval VARCHAR(50) NOT NULL CHECK (interval IN ('day', 'month')),
                description TEXT,
                features JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("Subscription tiers table ready");

        // Conversations table
pool.query(`
    CREATE TABLE IF NOT EXISTS conversations (
        id SERIAL PRIMARY KEY,
        user1_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        user2_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        last_message_at TIMESTAMP,
        UNIQUE (user1_id, user2_id)
    )
`).then(() => console.log("Conversations table ready"))
  .catch(err => console.error("Error creating conversations table:", err));

// Messages table
pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        read_at TIMESTAMP,
        status VARCHAR(20) DEFAULT 'sent'
    )
`).then(() => console.log("Messages table ready"))
  .catch(err => console.error("Error creating messages table:", err));

// Indexes for performance
pool.query(`
    CREATE INDEX IF NOT EXISTS idx_conversations_user1 ON conversations(user1_id);
    CREATE INDEX IF NOT EXISTS idx_conversations_user2 ON conversations(user2_id);
    CREATE INDEX IF NOT EXISTS idx_conversations_last_message ON conversations(last_message_at);
    CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
    CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
`).then(() => console.log("Messaging indexes ready"))
  .catch(err => console.error("Error creating messaging indexes:", err));

// Trigger to update last_message_at (using PostgreSQL function)
pool.query(`
    CREATE OR REPLACE FUNCTION update_conversation_timestamp()
    RETURNS TRIGGER AS $$
    BEGIN
        UPDATE conversations
        SET last_message_at = NEW.created_at
        WHERE id = NEW.conversation_id;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
`)
.then(() => {
    // Drop the trigger first if it exists
    return pool.query(`
        DROP TRIGGER IF EXISTS trg_update_conversation_timestamp ON messages;
    `);
})
.then(() => {
    // Create the trigger again
    return pool.query(`
        CREATE TRIGGER trg_update_conversation_timestamp
        AFTER INSERT ON messages
        FOR EACH ROW EXECUTE FUNCTION update_conversation_timestamp();
    `);
})
.then(() => console.log("Conversation timestamp trigger ready"))
.catch(err => {
    console.error("Error creating trigger/function:", err);
});
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) return res.status(401).json({ error: "No token provided" });
    try {
        const decoded = jwt.verify(token, secretKey);
        req.user = decoded;
        next();
    } catch (error) {
        console.error("Token verification error:", error);
        res.status(401).json({ error: "Invalid token" });
    }
};

// Verify Moderator
app.get("/verify-moderator", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, role FROM users WHERE id = $1 AND role IN ('moderator', 'admin')",
            [req.user.id]
        );
        if (result.rowCount === 0) {
            return res.status(403).json({ error: "Unauthorized: Moderator access required" });
        }
        res.json({ user: result.rows[0] });
    } catch (error) {
        console.error("Verify moderator error:", error);
        res.status(500).json({ error: "Server error", details: error.message });
    }
});

// Fetch Moderation Posts
app.get("/moderation/posts", authenticateToken, async (req, res) => {
    const { status = "all", search = "", sort = "reports", limit = "20", offset = "0" } = req.query;

    try {
        // Verify moderator role
        const userResult = await pool.query(
            "SELECT id FROM users WHERE id = $1 AND role IN ('moderator', 'admin')",
            [req.user.id]
        );
        if (userResult.rowCount === 0) {
            return res.status(403).json({ error: "Unauthorized: Moderator access required" });
        }

        const parsedLimit = parseInt(limit);
        const parsedOffset = parseInt(offset);
        if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
            return res.status(400).json({ error: "Limit must be between 1 and 100" });
        }
        if (isNaN(parsedOffset) || parsedOffset < 0) {
            return res.status(400).json({ error: "Offset must be non-negative" });
        }

        let query = `
            SELECT 
                p.id, p.user_id AS creator_id, p.type, p.title, p.caption, array_to_json(p.tags) AS tags,
                p.images, p.video_url, p.audio_url, p.created_at, p.status, p.views,
                p.duration, p.read_time, u.name AS creator_name, cp.profile_image AS creator_avatar,
                COUNT(DISTINCT l.id) AS likes, COUNT(DISTINCT c.id) AS comments,
                COUNT(DISTINCT r.id) AS report_count,
                array_agg(DISTINCT r.reason) AS report_reasons
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            LEFT JOIN creators_page cp ON p.user_id = cp.user_id
            LEFT JOIN likes l ON p.id = l.post_id
            LEFT JOIN comments c ON p.id = c.post_id
            LEFT JOIN reports r ON p.id = r.post_id
            WHERE p.is_draft = FALSE AND p.expires_at > NOW()
        `;
        const params = [];

        if (status !== "all") {
            query += ` AND p.status = $${params.length + 1}`;
            params.push(status);
        }
        if (search.trim()) {
            query += ` AND (p.title ILIKE $${params.length + 1} OR u.name ILIKE $${params.length + 1})`;
            params.push(`%${search.trim()}%`);
        }

        query += `
            GROUP BY p.id, u.name, cp.profile_image, p.views
        `;

        switch (sort) {
            case "reports":
                query += " ORDER BY report_count DESC, p.created_at DESC";
                break;
            case "newest":
                query += " ORDER BY p.created_at DESC";
                break;
            case "views":
                query += " ORDER BY p.views DESC";
                break;
            case "risk":
                query += " ORDER BY (COUNT(r.id) * 10 + CASE WHEN ARRAY['harassment', 'hate_speech'] && array_agg(r.reason) THEN 30 ELSE 0 END) DESC, p.created_at DESC";
                break;
            default:
                query += " ORDER BY p.created_at DESC";
        }

        query += ` LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
        params.push(parsedLimit, parsedOffset);

        const result = await pool.query(query, params);
        const posts = result.rows.map(post => ({
            id: post.id,
            creatorId: post.creator_id,
            type: post.type,
            title: post.title,
            caption: post.caption,
            tags: post.tags,
            images: post.images,
            video_url: post.video_url,
            audio_url: post.audio_url,
            created_at: post.created_at,
            status: post.status,
            creatorName: post.creator_name,
            creatorAvatar: post.creator_avatar || "https://placehold.co/40x40",
            likes: parseInt(post.likes) || 0,
            comments: parseInt(post.comments) || 0,
            views: parseInt(post.views) || 0,
            reportCount: parseInt(post.report_count) || 0,
            reportReasons: post.report_reasons.filter(r => r !== null) || [],
            duration: post.duration,
            read_time: post.read_time,
            creatorScore: Math.max(100 - post.report_count * 5, 0), // Placeholder: Decrease score based on reports
            riskScore: Math.min(post.report_count * 10 + (post.report_reasons.includes('harassment') || post.report_reasons.includes('hate_speech') ? 30 : 0), 100), // Placeholder: Based on report count and severity
            contentFlags: post.report_reasons.includes('hate_speech') ? ['potentially-controversial'] : [] // Placeholder: Flag based on report reasons
        }));

        const totalQuery = `
            SELECT COUNT(DISTINCT p.id)
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.is_draft = FALSE AND p.expires_at > NOW()
            ${status !== "all" ? `AND p.status = $1` : ""}
            ${search.trim() ? `AND (p.title ILIKE $2 OR u.name ILIKE $2)` : ""}
        `;
        const totalParams = status !== "all" ? [status] : [];
        if (search.trim()) totalParams.push(`%${search.trim()}%`);
        const totalResult = await pool.query(totalQuery, totalParams);

        res.json({
            posts,
            pagination: {
                limit: parsedLimit,
                offset: parsedOffset,
                total: parseInt(totalResult.rows[0].count)
            }
        });
    } catch (error) {
        console.error("Moderation posts fetch error:", error);
        res.status(500).json({ error: "Failed to fetch moderation posts", details: error.message });
    }
});

// Fetch Reports for a Post
app.get("/posts/:postId/reports", authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.postId);

    try {
        // Verify moderator role
        const userResult = await pool.query(
            "SELECT id FROM users WHERE id = $1 AND role IN ('moderator', 'admin')",
            [req.user.id]
        );
        if (userResult.rowCount === 0) {
            return res.status(403).json({ error: "Unauthorized: Moderator access required" });
        }

        if (isNaN(postId)) {
            return res.status(400).json({ error: "Invalid post ID" });
        }

        const result = await pool.query(
            `SELECT id AS report_id, post_id, reason, message, timestamp, status
             FROM reports
             WHERE post_id = $1
             ORDER BY timestamp DESC`,
            [postId]
        );

        res.json(result.rows.map(report => ({
            reportId: report.report_id,
            postId: report.post_id,
            reason: report.reason,
            message: report.message || "",
            timestamp: report.timestamp,
            status: report.status
        })));
    } catch (error) {
        console.error("Post reports fetch error:", error);
        res.status(500).json({ error: "Failed to fetch reports", details: error.message });
    }
});

// Update Post Status
app.patch("/posts/:postId/status", authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.postId);
    const { status, reason, comment } = req.body;

    try {
        // Verify moderator role
        const userResult = await pool.query(
            "SELECT id FROM users WHERE id = $1 AND role IN ('moderator', 'admin')",
            [req.user.id]
        );
        if (userResult.rowCount === 0) {
            return res.status(403).json({ error: "Unauthorized: Moderator access required" });
        }

        if (isNaN(postId)) {
            return res.status(400).json({ error: "Invalid post ID" });
        }

        const validStatuses = ["pending", "approved", "flagged", "restricted"];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: "Invalid status. Must be one of: " + validStatuses.join(", ") });
        }

        if (status === "flagged" && !reason) {
            return res.status(400).json({ error: "Reason is required for flagging" });
        }

        // Start transaction
        await pool.query("BEGIN");

        // Update post status
        const postResult = await pool.query(
            `UPDATE posts SET status = $1 WHERE id = $2 RETURNING id, status`,
            [status, postId]
        );
        if (postResult.rowCount === 0) {
            await pool.query("ROLLBACK");
            return res.status(404).json({ error: "Post not found" });
        }

        // Update reports status if resolved
        if (status === "approved" || status === "restricted") {
            await pool.query(
                "UPDATE reports SET status = 'resolved' WHERE post_id = $1",
                [postId]
            );
        }

        // Store moderation comment if provided
        if (comment) {
            await pool.query(
                `INSERT INTO moderation_comments (post_id, moderator_id, comment)
                 VALUES ($1, $2, $3)`,
                [postId, req.user.id, comment.trim()]
            );
        }

        // If flagged, add a report entry for moderator's action
        if (status === "flagged" && reason) {
            await pool.query(
                `INSERT INTO reports (post_id, creator_id, reporter_id, reason, message, timestamp, status)
                 VALUES ($1, (SELECT user_id FROM posts WHERE id = $1), $2, $3, $4, NOW(), 'pending')`,
                [postId, req.user.id, reason, comment || "Moderator flagged"]
            );
        }

        await pool.query("COMMIT");

        res.json({ message: `Post ${status} successfully`, postId });
    } catch (error) {
        await pool.query("ROLLBACK");
        console.error("Update post status error:", error);
        res.status(500).json({ error: "Failed to update post status", details: error.message });
    }
});

// Get M-Pesa OAuth Token
async function getAccessToken() {
    try {
        console.log("Consumer Key:", process.env.MPESA_CONSUMER_KEY);
        console.log("Consumer Secret:", process.env.MPESA_CONSUMER_SECRET);
        console.log("M-Pesa Environment:", process.env.MPESA_ENV);
        const response = await axios.get(
            process.env.MPESA_ENV === 'production'
                ? 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
                : 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
            {
                auth: {
                    username: process.env.MPESA_CONSUMER_KEY,
                    password: process.env.MPESA_CONSUMER_SECRET
                }
            }
        );
        console.log("OAuth Response:", JSON.stringify(response.data, null, 2));
        return response.data.access_token;
    } catch (error) {
        console.error("Access Token Error:", error.response?.data || error.message);
        throw new Error('Failed to generate M-Pesa access token: ' + error.message);
    }
}

// M-Pesa STK Push Endpoint
app.post("/api/mpesa/stkpush", authenticateToken, async (req, res) => {
    const { subscriptionId, amount, phoneNumber } = req.body;

    try {
        console.log("➡️ Received STK Push request:", { subscriptionId, amount, phoneNumber });

        // Validate and verify pending subscription
        if (!subscriptionId || isNaN(subscriptionId)) {
            return res.status(400).json({ error: "Invalid subscription ID" });
        }
        if (!amount || isNaN(amount) || amount <= 0) {
            return res.status(400).json({ error: "Invalid amount" });
        }
        if (!phoneNumber || !/^254\d{9}$/.test(phoneNumber)) {
            return res.status(400).json({ error: "Invalid phone number. Must be in 254XXXXXXXXX format" });
        }

        // Verify pending subscription
        const subResult = await pool.query(
            "SELECT id, payment_status FROM subscriptions WHERE id = $1 AND user_id = $2 AND payment_status = 'pending'",
            [subscriptionId, req.user.id]
        );
        if (subResult.rowCount === 0) {
            console.log("❌ No pending subscription found.");
            return res.status(404).json({ error: "Pending subscription not found" });
        }

        console.log("✅ Subscription confirmed. Fetching access token...");

        const token = await getAccessToken();
        console.log("🔐 Access token acquired:", token);

        const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3);
        console.log("🕒 Timestamp:", timestamp);

        const password = Buffer.from(`${process.env.PAYBILL_NUMBER}${process.env.PASSKEY}${timestamp}`).toString('base64');

        console.log("📞 Initiating STK Push to Safaricom API");

        const response = await axios.post(
            process.env.MPESA_ENV === 'production'
                ? 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
                : 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            {
                BusinessShortCode: process.env.PAYBILL_NUMBER,
                Password: password,
                Timestamp: timestamp,
                TransactionType: 'CustomerPayBillOnline',
                Amount: amount,
                PartyA: phoneNumber,
                PartyB: process.env.PAYBILL_NUMBER,
                PhoneNumber: phoneNumber,
                CallBackURL: process.env.MPESA_CALLBACK_URL,
                AccountReference: `MPP_Sub_${subscriptionId}`,
                TransactionDesc: 'My Paid Posts Subscription'
            },
            { headers: { Authorization: `Bearer ${token}` } }
        );

        console.log("✅ STK Push initiated:", response.data.CheckoutRequestID);

        // Save the CheckoutRequestID in mpesa_transaction_id
        await pool.query(
            "UPDATE subscriptions SET mpesa_transaction_id = $1 WHERE id = $2",
            [response.data.CheckoutRequestID, subscriptionId]
        );

        res.json({ success: true, data: response.data });
    } catch (error) {
        console.error("❌ STK Push error:", error.response?.data || error.message);
        res.status(500).json({ error: "Payment initiation failed: " + (error.response?.data?.error || error.message) });
    }
});

// Update /api/mpesa/callback to insert into transactions
app.post("/api/mpesa/callback", async (req, res) => {
    try {
        console.log("📥 Full Callback Payload:", JSON.stringify(req.body, null, 2));

        const stkCallback = req.body.Body?.stkCallback;
        if (!stkCallback || typeof stkCallback.ResultCode === 'undefined') {
            console.error("❌ Invalid callback structure received:", JSON.stringify(req.body, null, 2));
            return res.status(400).json({ error: "Invalid callback data" });
        }

        const { ResultCode, ResultDesc, CallbackMetadata, CheckoutRequestID } = stkCallback;
        console.log("ℹ️ Extracted fields =>", { ResultCode, ResultDesc, CheckoutRequestID });

        const transactionId = CallbackMetadata?.Item.find(item => item.Name === 'MpesaReceiptNumber')?.Value || null;
        console.log("💳 Mpesa Receipt Number:", transactionId || "N/A");

        // Find the subscription using the CheckoutRequestID
        const subResult = await pool.query(
            "SELECT id, creator_id, amount FROM subscriptions WHERE mpesa_transaction_id = $1",
            [CheckoutRequestID]
        );

        if (subResult.rowCount === 0) {
            console.error("❌ No matching subscription found for CheckoutRequestID:", CheckoutRequestID);
            return res.status(404).json({ error: "Subscription not found for this transaction" });
        }

        const subscriptionId = subResult.rows[0].id;
        const creatorId = subResult.rows[0].creator_id;
        const amount = subResult.rows[0].amount;

        const status = ResultCode === 0 ? 'completed' : 'failed';
        console.log(`✅ Payment ${status.toUpperCase()} for subscription ID: ${subscriptionId}`);

        // Start transaction
        await pool.query("BEGIN");

        // Update subscriptions
        await pool.query(
            "UPDATE subscriptions SET payment_status = $1, mpesa_transaction_id = $2 WHERE id = $3",
            [status, transactionId || CheckoutRequestID, subscriptionId]
        );

        // Insert into transactions
        await pool.query(
            `INSERT INTO transactions (creator_id, type, amount, status, transaction_id, description, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
            [
                creatorId,
                'subscription',
                amount,
                status,
                transactionId || CheckoutRequestID,
                `Subscription payment for ID ${subscriptionId}`
            ]
        );

        await pool.query("COMMIT");

        res.sendStatus(200);
    } catch (error) {
        await pool.query("ROLLBACK");
        console.error("❌ Callback processing error:", error.stack || error.message);
        res.status(500).json({ error: "Failed to process callback" });
    }
});


// Subscription Status Endpoint
app.get("/api/subscription/status/:subscriptionId", authenticateToken, async (req, res) => {
    const { subscriptionId } = req.params;
    try {
        const result = await pool.query(
            "SELECT payment_status, plan, amount, end_date FROM subscriptions WHERE id = $1 AND user_id = $2",
            [subscriptionId, req.user.id]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: "Subscription not found" });
        }
        res.json({ status: result.rows[0].payment_status, subscription: result.rows[0] });
    } catch (error) {
        console.error("Subscription status error:", error);
        res.status(500).json({ error: "Failed to fetch subscription status" });
    }
});

// Subscribe Endpoint
app.post("/subscribe", authenticateToken, async (req, res) => {
    const { creator_id, tier_id, plan, duration_days, amount, payment_method, payment_details } = req.body;
    const userId = req.user.id;

    try {
        // Validate inputs
        if (!creator_id || isNaN(creator_id)) {
            return res.status(400).json({ error: "Invalid creator ID" });
        }
        if (!tier_id || isNaN(tier_id)) {
            return res.status(400).json({ error: "Invalid tier ID" });
        }
        if (!plan) {
            return res.status(400).json({ error: "Plan is required" });
        }
        if (!duration_days || isNaN(duration_days) || duration_days < 1 || duration_days > 365) {
            return res.status(400).json({ error: "Invalid duration, must be between 1 and 365 days" });
        }
        if (!amount || isNaN(amount) || amount <= 0) {
            return res.status(400).json({ error: "Invalid amount" });
        }
        if (!['mpesa', 'card'].includes(payment_method)) {
            return res.status(400).json({ error: "Invalid payment method. Must be 'mpesa' or 'card'" });
        }
        if (!payment_details || typeof payment_details !== 'object') {
            return res.status(400).json({ error: "Payment details are required" });
        }
        if (payment_method === 'mpesa') {
            if (!payment_details.phone || !/^254\d{9}$/.test(payment_details.phone)) {
                return res.status(400).json({ error: "Invalid M-Pesa phone number" });
            }
        } else {
            return res.status(400).json({ error: "Card payments are not yet supported" });
        }
        if (parseInt(creator_id) === userId) {
            return res.status(400).json({ error: "Cannot subscribe to yourself" });
        }

        // Verify creator exists
        const creatorResult = await pool.query(
            `SELECT u.id FROM users u JOIN creators_page cp ON u.id = cp.user_id WHERE u.id = $1`,
            [creator_id]
        );
        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ error: "Creator not found or not a creator account" });
        }

        // Validate tier
        const tierResult = await pool.query(
            `SELECT id, name, price, interval FROM subscription_tiers 
             WHERE id = $1 AND creator_id = $2 AND interval IN ('month', 'day')`,
            [tier_id, creator_id]
        );
        if (tierResult.rowCount === 0) {
            return res.status(404).json({ error: "Subscription tier not found, not owned by creator, or not Monthly/Daily" });
        }

        const tier = tierResult.rows[0];

        // Validate duration and amount
        let validatedDuration = duration_days;
        let validatedAmount = amount;
        if (tier.interval === 'month') {
            if (duration_days !== 30) {
                return res.status(400).json({ error: "Monthly plans must have a duration of 30 days" });
            }
            if (amount !== tier.price) {
                return res.status(400).json({ error: `Amount must be ${tier.price} for monthly plan` });
            }
        } else if (tier.interval === 'day') {
            if (amount !== tier.price * duration_days) {
                return res.status(400).json({ error: `Amount must be ${tier.price} * ${duration_days} = ${tier.price * duration_days} for daily plan` });
            }
        }

        // Check for existing active subscription
        const existingSub = await pool.query(
            `SELECT id FROM subscriptions WHERE user_id = $1 AND creator_id = $2 AND end_date > CURRENT_DATE AND payment_status = 'completed'`,
            [userId, creator_id]
        );
        if (existingSub.rowCount > 0) {
            return res.status(400).json({ error: "You already have an active subscription to this creator" });
        }

        // Check for pending or failed subscription
        const pendingOrFailedSub = await pool.query(
            `SELECT id FROM subscriptions WHERE user_id = $1 AND creator_id = $2 AND payment_status IN ('pending', 'failed')`,
            [userId, creator_id]
        );

        // Calculate dates
        const startDate = new Date().toISOString().split('T')[0];
        const endDate = new Date();
        endDate.setUTCDate(endDate.getUTCDate() + validatedDuration);
        const endDateStr = endDate.toISOString().split('T')[0];

        let result;
        if (pendingOrFailedSub.rowCount > 0) {
            // Update existing pending/failed subscription
            result = await pool.query(
                `UPDATE subscriptions 
                 SET plan = $1, start_date = $2, end_date = $3, amount = $4, payment_method = $5, payment_status = $6, mpesa_transaction_id = NULL
                 WHERE id = $7
                 RETURNING id, user_id, creator_id, plan, start_date, end_date, amount, payment_method, payment_status`,
                [
                    tier.name,
                    startDate,
                    endDateStr,
                    validatedAmount,
                    payment_method,
                    'pending',
                    pendingOrFailedSub.rows[0].id
                ]
            );
        } else {
            // Insert new subscription
            result = await pool.query(
                `INSERT INTO subscriptions (user_id, creator_id, plan, start_date, end_date, amount, payment_method, payment_status)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 RETURNING id, user_id, creator_id, plan, start_date, end_date, amount, payment_method, payment_status`,
                [
                    userId,
                    creator_id,
                    tier.name,
                    startDate,
                    endDateStr,
                    validatedAmount,
                    payment_method,
                    'pending'
                ]
            );
        }

        // Trigger STK Push for M-Pesa
        if (payment_method === 'mpesa') {
            const subscriptionId = result.rows[0].id;
            const phoneNumber = payment_details.phone;

            const stkResponse = await axios.post(
                `${process.env.API_BASE_URL || 'https://mpp-backend-service.onrender.com'}/api/mpesa/stkpush`,
                { subscriptionId, amount: validatedAmount, phoneNumber },
                { headers: { Authorization: `Bearer ${req.headers.authorization.split(' ')[1]}` } }
            );

            if (!stkResponse.data.success) {
                console.error("STK Push Response:", stkResponse.data);
                await pool.query("DELETE FROM subscriptions WHERE id = $1", [subscriptionId]);
                return res.status(500).json({ error: "Failed to initiate M-Pesa payment", details: stkResponse.data.error });
            }
        }

        res.status(201).json({
            message: "Subscription created or updated, payment initiated",
            subscription: result.rows[0]
        });
    } catch (error) {
        console.error("Subscribe error:", error);
        if (error.code === "23505") {
            return res.status(400).json({ error: "Subscription already exists" });
        }
        res.status(500).json({
            error: "Failed to create or update subscription",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Signup
app.post("/signup", async (req, res) => {
    const { name, email, password, moderatorId, moderator, role } = req.body;
    try {
        if (!name || !email || !password) {
            return res.status(400).json({ error: "Name, email, and password are required" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        let finalModeratorId = moderatorId || 'Md-1';
        if (moderatorId) {
            const moderatorResult = await pool.query(
                "SELECT id, name FROM users WHERE user_moderation_id = $1",
                [moderatorId]
            );
            if (moderatorResult.rowCount === 0) {
                return res.status(400).json({ error: "Invalid moderator ID" });
            }
            if (moderator && moderator !== moderatorResult.rows[0].name) {
                return res.status(400).json({ error: "Moderator name does not match ID" });
            }
        }

        const validRoles = ["user", "moderator", "admin"];
        const finalRole = validRoles.includes(role) ? role : "user";

        const sequenceResult = await pool.query(
            "SELECT nextval('user_moderation_seq') AS seq"
        );
        const userModerationId = `Md-${sequenceResult.rows[0].seq}`;

        const result = await pool.query(
            "INSERT INTO users (name, email, password, moderator_id, moderator, user_moderation_id, role) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, email, moderator_id, moderator, user_moderation_id, role",
            [name, email, hashedPassword, finalModeratorId, moderator || '', userModerationId, finalRole]
        );
        res.status(201).json({ message: "User created", user: result.rows[0] });
    } catch (error) {
        if (error.code === "23505") {
            res.status(400).json({ error: "Email already exists" });
        } else {
            console.error("Signup error:", error);
            res.status(500).json({ error: "Server error", details: error.message });
        }
    }
});

// Login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        if (!user) {
            return res.status(400).json({ error: "Invalid email or password" });
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: "Invalid email or password" });
        }
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, secretKey, { expiresIn: "1h" });
        res.json({ message: "Login successful", token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Server error", details: error.message });
    }
});

// Verify token
app.get("/verify", authenticateToken, async (req, res) => {
    try {
        const userResult = await pool.query(
            "SELECT id, name, email, bio, categories, role FROM users WHERE id = $1",
            [req.user.id]
        );
        const user = userResult.rows[0];
        if (!user) return res.status(404).json({ error: "User not found" });

        const creatorPageResult = await pool.query(
            "SELECT profile_image FROM creators_page WHERE user_id = $1",
            [req.user.id]
        );
        const profileImage = creatorPageResult.rows[0]?.profile_image || null;

        const creatorResult = await pool.query(
            "SELECT user_id FROM creators_page WHERE user_id = $1",
            [req.user.id]
        );
        const isCreator = creatorResult.rowCount > 0;

        res.json({
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                bio: user.bio,
                categories: user.categories,
                profile_image: profileImage,
                isCreator: isCreator,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Verify error:", error);
        res.status(500).json({ error: "Server error", details: error.message });
    }
});

// Update Profile
app.put("/profile", authenticateToken, async (req, res) => {
    const { name, email, bio, categories } = req.body;
    try {
        const result = await pool.query(
            "UPDATE users SET name = $1, email = $2, bio = $3, categories = $4 WHERE id = $5 RETURNING id, name, email, bio, categories, role",
            [name, email, bio, categories, req.user.id]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: "User not found" });
        res.json({ message: "Profile updated", user: result.rows[0] });
    } catch (error) {
        if (error.code === "23505") {
            res.status(400).json({ error: "Email already in use" });
        } else {
            console.error("Profile update error:", error);
            res.status(500).json({ error: "Server error", details: error.message });
        }
    }
});


// Creators Page Endpoint
app.put("/creators-page", authenticateToken, uploadLimiter, async (req, res) => {
    const { profile, bio, socials } = req.body;
    const userId = req.user.id;

    try {
        // Validate inputs
        if (!profile || !socials) {
            return res.status(400).json({ error: "Profile and socials are required" });
        }

        // Start transaction
        await pool.query("BEGIN");

        // Update bio in users table if provided
        if (bio) {
            await pool.query("UPDATE users SET bio = $1 WHERE id = $2", [bio, userId]);
        }

        // Check if user already has a creator page
        const existingCreator = await pool.query(
            "SELECT user_id FROM creators_page WHERE user_id = $1",
            [userId]
        );

        // Insert or update creators_page
        const creatorResult = await pool.query(
            `INSERT INTO creators_page (user_id, profile_image, socials)
             VALUES ($1, $2, $3)
             ON CONFLICT (user_id)
             DO UPDATE SET profile_image = $2, socials = $3, updated_at = CURRENT_TIMESTAMP
             RETURNING user_id, profile_image, socials`,
            [userId, profile, JSON.stringify(socials)]
        );

        // Replace the existing default tiers logic
if (existingCreator.rowCount === 0) {
    const defaultTiers = [
        {
            name: "Monthly Membership",
            price: 140,
            interval: "month",
            description: "Access to exclusive posts and early content.",
            features: ["Exclusive posts", "Early access to content", "Direct messaging with creator"],
        },
        {
            name: "Daily Membership",
            price: 1,
            interval: "day",
            description: "Access to exclusive posts and early content.",
            features: ["Exclusive posts", "Early access to content", "Direct messaging with creator"],
        },
    ];

    // Ensure exactly two tiers
    const existingTiers = await pool.query(
        `SELECT COUNT(*) FROM subscription_tiers WHERE creator_id = $1`,
        [userId]
    );
    if (parseInt(existingTiers.rows[0].count) > 0) {
        throw new Error("Creator already has tiers assigned");
    }

    for (const tier of defaultTiers) {
        await pool.query(
            `INSERT INTO subscription_tiers (creator_id, name, price, interval, description, features)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT DO NOTHING`,
            [userId, tier.name, tier.price, tier.interval, tier.description, JSON.stringify(tier.features)]
        );
    }
    console.log(`[creators-page] Assigned default Monthly and Daily tiers for creator userId=${userId}`);
}
        // Update user to mark as creator
        await pool.query(
            "UPDATE users SET is_creator = true WHERE id = $1",
            [userId]
        );

        // Commit transaction
        await pool.query("COMMIT");

        res.status(200).json({
            message: existingCreator.rowCount > 0 ? "Creator page updated successfully" : "Creator page created successfully",
            creatorsPage: {
                userId: creatorResult.rows[0].user_id,
                profile_image: creatorResult.rows[0].profile_image,
                socials: creatorResult.rows[0].socials,
            },
        });
    } catch (error) {
        await pool.query("ROLLBACK");
        console.error("[creators-page] Error:", error);
        res.status(500).json({
            error: "Failed to create or update creator page",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined,
        });
    }
});


// Fetch Creators Page
app.get("/creators-page", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT profile_image, socials FROM creators_page WHERE user_id = $1", [req.user.id]);
        const creatorsPage = result.rows[0] || { profile_image: "", socials: {} };
        res.json({ creatorsPage });
    } catch (error) {
        console.error("Creators page fetch error:", error);
        res.status(500).json({ error: "Server error", details: error.message });
    }
});

// Upload Image
app.post("/upload-image", authenticateToken, uploadLimiter, upload.single("image"), async (req, res) => {
    try {
        const userId = req.user.id;
        const type = req.body.type;
        const file = req.file;

        if (!file) return res.status(400).json({ error: "No image provided" });

        const fileName = `${userId}/${type}-${Date.now()}.${file.mimetype.split("/")[1]}`;
        const { data, error } = await supabase.storage
            .from("users")
            .upload(fileName, file.buffer, { contentType: file.mimetype });
        if (error) {
            console.error("Supabase error details:", error);
            throw new Error(`Supabase upload failed: ${error.message}`);
        }

        const { data: urlData } = supabase.storage.from("users").getPublicUrl(fileName);
        const publicURL = urlData.publicUrl;

        res.set('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
        res.json({ url: publicURL });
    } catch (error) {
        console.error("Image upload error:", error);
        res.status(500).json({ error: error.message || "Failed to upload image" });
    }
});

// Create Post
app.post("/posts", authenticateToken, uploadLimiter, upload.fields([
    { name: "images", maxCount: 20 },
    { name: "video_url", maxCount: 1 },
    { name: "audio_url", maxCount: 1 }
]), async (req, res) => {
    const { type, title, caption, tags, isPremium, isDraft, scheduled, visibility } = req.body;
    const userId = req.user.id;
    const files = {
        images: req.files["images"] || [],
        video_url: req.files["video_url"] || [],
        audio_url: req.files["audio_url"] || []
    };

    try {
        const validTypes = ["image", "video", "audio", "article", "gallery"];
        if (!validTypes.includes(type)) {
            return res.status(400).json({ error: "Invalid post type" });
        }

        const limits = {
            image: { maxCount: 1, maxSize: 10 * 1024 * 1024 },
            video: { maxCount: 1, maxSize: 100 * 1024 * 1024 },
            audio: { maxCount: 1, maxSize: 50 * 1024 * 1024 },
            article: { maxCount: 1, maxSize: 10 * 1024 * 1024 },
            gallery: { maxCount: 20, maxSize: 10 * 1024 * 1024 }
        };

        const typeLimits = limits[type];
        let targetFiles = files.images;
        if (type === "video") targetFiles = files.video_url;
        if (type === "audio") targetFiles = files.audio_url;

        if (targetFiles.length > typeLimits.maxCount) {
            return res.status(400).json({ error: `Maximum ${typeLimits.maxCount} file(s) allowed for ${type}` });
        }
        for (const file of targetFiles) {
            if (file.size > typeLimits.maxSize) {
                return res.status(400).json({ error: `File size exceeds ${typeLimits.maxSize / 1024 / 1024}MB limit for ${type}` });
            }
            const allowedMime = type === "video" ? "video/" : type === "audio" ? "audio/" : "image/";
            if (!file.mimetype.startsWith(allowedMime)) {
                return res.status(400).json({ error: `Invalid file type for ${type}` });
            }
        }

        let fileUrls = [], videoUrl = null, audioUrl = null;
        for (const file of targetFiles) {
            const fileName = `${userId}/${type}-${Date.now()}-${Math.random().toString(36).substring(2, 8)}.${file.mimetype.split("/")[1]}`;
            const { data, error } = await supabase.storage
                .from("users")
                .upload(fileName, file.buffer, { contentType: file.mimetype });
            if (error) throw new Error(`File upload failed: ${error.message}`);
            const { data: urlData } = supabase.storage.from("users").getPublicUrl(fileName);
            if (type === "video") {
                videoUrl = urlData.publicUrl;
            } else if (type === "audio") {
                audioUrl = urlData.publicUrl;
            } else {
                fileUrls.push(urlData.publicUrl);
            }
        }

        let scheduledAt = null;
        if (scheduled && scheduled !== "") {
            const { date, time } = JSON.parse(scheduled);
            scheduledAt = new Date(`${date}T${time}:00Z`).toISOString();
            if (new Date(scheduledAt) < new Date()) {
                return res.status(400).json({ error: "Scheduled time must be in the future" });
            }
        }

        let readTime = null;
        if (type === "article" && caption) {
            const wordCount = caption.trim().split(/\s+/).length;
            readTime = Math.ceil(wordCount / 200);
        }

        const result = await pool.query(
            `INSERT INTO posts 
             (user_id, type, title, caption, tags, images, video_url, audio_url, is_premium, is_draft, scheduled_at, visibility, read_time, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             RETURNING *`,
            [
                userId,
                type,
                title || "",
                caption || "",
                tags ? JSON.parse(tags) : [],
                JSON.stringify(fileUrls),
                videoUrl,
                audioUrl,
                isPremium === "true",
                isDraft === "true",
                scheduledAt,
                visibility || "public",
                readTime,
                'pending' // All new posts start as pending
            ]
        );

        const post = result.rows[0];
        res.set('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
        res.status(201).json({ message: "Post created", post });
    } catch (error) {
        console.error("Post creation error:", error);
        res.status(500).json({ error: "Failed to create post", details: error.message });
    }
});

// Fetch Posts
app.get("/posts", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(
            `SELECT 
               id, type, title, caption, array_to_json(tags) AS tags,
               images, video_url, audio_url, created_at, expires_at,
               is_draft, is_premium, scheduled_at, visibility, read_time, duration, status
             FROM posts
             WHERE user_id = $1 AND expires_at > NOW()
             ORDER BY created_at DESC`,
            [userId]
        );
        res.json({ posts: result.rows });
    } catch (error) {
        console.error("Post fetch error:", { message: error.message, stack: error.stack, userId });
        res.status(500).json({
            error: "Failed to fetch posts",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Fetch Public Posts for Explore Section
app.get("/explore", async (req, res) => {
    const { type = "all", category = "all", sort = "trending", limit = "20", offset = "0" } = req.query;

    const validTypes = ["all", "image", "video", "audio", "article", "gallery"];
    if (!validTypes.includes(type)) {
        return res.status(400).json({ error: "Invalid type" });
    }
    const parsedLimit = parseInt(limit);
    const parsedOffset = parseInt(offset);
    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
        return res.status(400).json({ error: "Limit must be between 1 and 100" });
    }
    if (isNaN(parsedOffset) || parsedOffset < 0) {
        return res.status(400).json({ error: "Offset must be non-negative" });
    }

    try {
        let query = `
            SELECT 
                p.id, p.user_id AS creator_id, p.type, p.title, p.caption, array_to_json(p.tags) AS tags, 
                p.images, p.video_url, p.audio_url, p.created_at, p.is_premium, p.visibility, 
                p.read_time, p.duration, p.status, u.name AS creator_name, cp.profile_image AS creator_avatar,
                COUNT(DISTINCT l.id) AS likes, COUNT(DISTINCT c.id) AS comments,
                p.views
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            LEFT JOIN creators_page cp ON p.user_id = cp.user_id
            LEFT JOIN likes l ON p.id = l.post_id
            LEFT JOIN comments c ON p.id = c.post_id
            WHERE p.visibility = 'public' AND p.is_draft = FALSE AND p.expires_at > NOW() AND p.status IN ('pending', 'approved')
        `;
        const params = [];

        if (type !== "all") {
            query += ` AND p.type = $${params.length + 1}`;
            params.push(type);
        }
        if (category !== "all") {
            query += ` AND $${params.length + 1} = ANY(p.tags)`;
            params.push(category);
        }
        if (sort === "trending") {
            query += ` AND p.created_at > NOW() - INTERVAL '7 days'`;
        }

        query += `
            GROUP BY p.id, p.user_id, u.name, cp.profile_image, p.views
        `;

        switch (sort) {
            case "newest":
                query += " ORDER BY p.created_at DESC";
                break;
            case "most_popular":
                query += " ORDER BY (COUNT(l.id) + COUNT(c.id)) DESC, p.created_at DESC";
                break;
            case "recommended":
                query += " ORDER BY RANDOM()";
                break;
            case "trending":
            default:
                query += " ORDER BY (COUNT(l.id) + COUNT(c.id)) DESC, p.created_at DESC";
                break;
        }

        query += ` LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
        params.push(parsedLimit, parsedOffset);

        const result = await pool.query(query, params);
        const posts = result.rows.map(post => ({
            id: post.id,
            creatorId: post.creator_id,
            type: post.type,
            title: post.title,
            caption: post.caption,
            tags: post.tags,
            images: post.images,
            video_url: post.video_url,
            audio_url: post.audio_url,
            created_at: post.created_at,
            isPremium: post.is_premium,
            visibility: post.visibility,
            creatorName: post.creator_name,
            creatorAvatar: post.creator_avatar || "https://placehold.co/40x40",
            likes: parseInt(post.likes) || 0,
            comments: parseInt(post.comments) || 0,
            views: parseInt(post.views) || 0,
            duration: post.duration,
            read_time: post.read_time,
            isLiked: false // Default to false since user_id is not passed
        }));

        const totalQuery = `
            SELECT COUNT(*) 
            FROM posts p 
            WHERE p.visibility = 'public' AND p.is_draft = FALSE AND p.expires_at > NOW() AND p.status IN ('pending', 'approved')
            ${type !== "all" ? "AND p.type = $1" : ""}
            ${category !== "all" ? `AND $${type !== "all" ? "2" : "1"} = ANY(p.tags)` : ""}
            ${sort === "trending" ? "AND p.created_at > NOW() - INTERVAL '7 days'" : ""}
        `;
        const totalParams = type !== "all" ? [type] : [];
        if (category !== "all") totalParams.push(category);
        const totalResult = await pool.query(totalQuery, totalParams);

        res.json({
            posts,
            pagination: {
                limit: parsedLimit,
                offset: parsedOffset,
                total: parseInt(totalResult.rows[0].count)
            }
        });
    } catch (error) {
        console.error("Explore fetch error:", error);
        res.status(500).json({ error: "Failed to fetch explore posts", details: error.message });
    }
});

// Get a single public post by ID
app.get("/post/:id", async (req, res) => {
    const postId = parseInt(req.params.id);

    if (isNaN(postId)) {
        return res.status(400).json({ error: "Invalid post ID" });
    }

    try {
        const result = await pool.query(
            `SELECT 
                p.id, p.user_id AS creator_id, p.type, p.title, p.caption, array_to_json(p.tags) AS tags,
                p.images, p.video_url, p.audio_url, p.created_at, p.is_premium, p.visibility,
                p.read_time, p.duration, p.status, u.name AS creator_name, cp.profile_image AS creator_avatar,
                COUNT(DISTINCT l.id) AS likes, COUNT(DISTINCT c.id) AS comments,
                p.views
             FROM posts p
             LEFT JOIN users u ON p.user_id = u.id
             LEFT JOIN creators_page cp ON p.user_id = cp.user_id
             LEFT JOIN likes l ON p.id = l.post_id
             LEFT JOIN comments c ON p.id = c.post_id
             WHERE p.id = $1 AND p.visibility = 'public' AND p.is_draft = FALSE AND p.expires_at > NOW() AND p.status IN ('pending', 'approved')
             GROUP BY p.id, u.name, cp.profile_image, p.views`,
            [postId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        const post = result.rows[0];

        res.json({
            id: post.id,
            creatorId: post.creator_id,
            type: post.type,
            title: post.title,
            caption: post.caption,
            tags: post.tags,
            images: post.images,
            video_url: post.video_url,
            audio_url: post.audio_url,
            created_at: post.created_at,
            isPremium: post.is_premium,
            visibility: post.visibility,
            creatorName: post.creator_name,
            creatorAvatar: post.creator_avatar || "https://placehold.co/40x40",
            likes: parseInt(post.likes) || 0,
            comments: parseInt(post.comments) || 0,
            views: parseInt(post.views) || 0,
            duration: post.duration,
            read_time: post.read_time,
        });
    } catch (error) {
        console.error("Single post fetch error:", error);
        res.status(500).json({ error: "Failed to fetch post", details: error.message });
    }
});

// Track View on Post
app.post("/posts/:id/view", authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.id);
    const userId = req.user.id;

    try {
        // Validate post ID
        if (isNaN(postId)) {
            return res.status(400).json({ error: "Invalid post ID" });
        }

        // Check if post exists and is accessible
        const postResult = await pool.query(
            "SELECT id, views FROM posts WHERE id = $1 AND visibility = 'public' AND is_draft = FALSE AND expires_at > NOW() AND status IN ('pending', 'approved')",
            [postId]
        );
        if (postResult.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        // Check if user has already viewed the post
        const viewResult = await pool.query(
            "SELECT id FROM views WHERE user_id = $1 AND post_id = $2",
            [userId, postId]
        );

        if (viewResult.rowCount > 0) {
            return res.status(400).json({ error: "View already recorded for this post", views: postResult.rows[0].views });
        }

        // Start transaction to ensure atomicity
        await pool.query("BEGIN");

        // Increment views in posts table
        const newViews = (postResult.rows[0].views || 0) + 1;
        await pool.query(
            "UPDATE posts SET views = $1 WHERE id = $2",
            [newViews, postId]
        );

        // Record view in views table
        await pool.query(
            "INSERT INTO views (user_id, post_id) VALUES ($1, $2)",
            [userId, postId]
        );

        // Commit transaction
        await pool.query("COMMIT");

        res.json({ message: "View recorded", views: newViews });
    } catch (error) {
        await pool.query("ROLLBACK");
        console.error("View tracking error:", error);
        if (error.code === "23505") {
            return res.status(400).json({ error: "View already recorded for this post" });
        }
        res.status(500).json({ error: "Failed to record view", details: error.message });
    }
});

// Toggle Like on Post
app.post("/posts/:id/like", authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.id);
    const userId = req.user.id;

    try {
        const postResult = await pool.query(
            "SELECT id FROM posts WHERE id = $1 AND visibility = 'public' AND is_draft = FALSE AND expires_at > NOW() AND status IN ('pending', 'approved')",
            [postId]
        );
        if (postResult.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        const likeResult = await pool.query(
            "SELECT id FROM likes WHERE user_id = $1 AND post_id = $2",
            [userId, postId]
        );

        if (likeResult.rowCount > 0) {
            await pool.query(
                "DELETE FROM likes WHERE user_id = $1 AND post_id = $2",
                [userId, postId]
            );
            const newLikeCount = await pool.query(
                "SELECT COUNT(*) AS count FROM likes WHERE post_id = $1",
                [postId]
            );
            res.json({ message: "Post unliked", likes: parseInt(newLikeCount.rows[0].count), isLiked: false });
        } else {
            await pool.query(
                "INSERT INTO likes (user_id, post_id) VALUES ($1, $2)",
                [userId, postId]
            );
            const newLikeCount = await pool.query(
                "SELECT COUNT(*) AS count FROM likes WHERE post_id = $1",
                [postId]
            );
            res.json({ message: "Post liked", likes: parseInt(newLikeCount.rows[0].count), isLiked: true });
        }
    } catch (error) {
        console.error("Like toggle error:", error);
        if (error.code === "23505") {
            return res.status(400).json({ error: "Like already exists" });
        }
        res.status(500).json({ error: "Failed to toggle like", details: error.message });
    }
});

// Fetch Comments for a Post
app.get("/posts/:id/comments", async (req, res) => {
    const postId = parseInt(req.params.id);
    const limit = 6;

    try {
        const postResult = await pool.query(
            "SELECT id FROM posts WHERE id = $1 AND visibility = 'public' AND is_draft = FALSE AND expires_at > NOW() AND status IN ('pending', 'approved')",
            [postId]
        );
        if (postResult.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        const result = await pool.query(
            `SELECT 
                c.id, c.content, c.created_at, 
                u.id AS user_id, u.name AS user_name, cp.profile_image AS user_avatar
             FROM comments c
             JOIN users u ON c.user_id = u.id
             LEFT JOIN creators_page cp ON u.id = cp.user_id
             WHERE c.post_id = $1
             ORDER BY c.created_at DESC
             LIMIT $2`,
            [postId, limit]
        );

        const comments = result.rows.map(comment => ({
            id: comment.id,
            content: comment.content,
            created_at: comment.created_at,
            user: {
                id: comment.user_id,
                name: comment.user_name,
                avatar: comment.user_avatar || "https://placehold.co/40x40"
            }
        }));

        const totalComments = await pool.query(
            "SELECT COUNT(*) AS count FROM comments WHERE post_id = $1",
            [postId]
        );

        res.json({
            comments,
            total: parseInt(totalComments.rows[0].count)
        });
    } catch (error) {
        console.error("Comments fetch error:", error);
        res.status(500).json({ error: "Failed to fetch comments", details: error.message });
    }
});

// Add Comment to a Post
app.post("/posts/:id/comments", authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.id);
    const userId = req.user.id;
    const { content } = req.body;

    try {
        if (!content || content.trim().length === 0) {
            return res.status(400).json({ error: "Comment content is required" });
        }
        if (content.length > 500) {
            return res.status(400).json({ error: "Comment cannot exceed 500 characters" });
        }

        const postResult = await pool.query(
            "SELECT id FROM posts WHERE id = $1 AND visibility = 'public' AND is_draft = FALSE AND expires_at > NOW() AND status IN ('pending', 'approved')",
            [postId]
        );
        if (postResult.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        const result = await pool.query(
            `INSERT INTO comments (user_id, post_id, content)
             VALUES ($1, $2, $3)
             RETURNING id, content, created_at`,
            [userId, postId, content.trim()]
        );

        const userResult = await pool.query(
            "SELECT u.id, u.name, cp.profile_image FROM users u LEFT JOIN creators_page cp ON u.id = cp.user_id WHERE u.id = $1",
            [userId]
        );

        const comment = {
            id: result.rows[0].id,
            content: result.rows[0].content,
            created_at: result.rows[0].created_at,
            user: {
                id: userResult.rows[0].id,
                name: userResult.rows[0].name,
                avatar: userResult.rows[0].profile_image || "https://placehold.co/40x40"
            }
        };

        const newCommentCount = await pool.query(
            "SELECT COUNT(*) AS count FROM comments WHERE post_id = $1",
            [postId]
        );

        res.status(201).json({
            message: "Comment added",
            comment,
            comments: parseInt(newCommentCount.rows[0].count)
        });
    } catch (error) {
        console.error("Comment creation error:", error);
        res.status(500).json({ error: "Failed to add comment", details: error.message });
    }
});

// Fetch Creator Profile by Name
app.get("/creator/:creatorName", async (req, res) => {
    const { creatorName } = req.params;
    const userId = req.user?.id;

    try {
        const creatorResult = await pool.query(
            `SELECT 
               u.id, u.name, u.bio, u.categories,
               cp.profile_image, cp.socials
             FROM users u
             LEFT JOIN creators_page cp ON u.id = cp.user_id
             WHERE LOWER(u.name) = $1 OR LOWER(REPLACE(u.name, ' ', '-')) = $1`,
            [creatorName.toLowerCase()]
        );

        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ error: "Creator not found" });
        }

        const creator = creatorResult.rows[0];
        const isCreator = !!creator.profile_image || !!creator.socials;

        if (!isCreator) {
            return res.status(404).json({ error: "User is not a creator" });
        }

        const postsResult = await pool.query(
            `SELECT 
               p.id, p.type, p.title, p.caption, array_to_json(p.tags) AS tags,
               p.images, p.video_url, p.audio_url, p.created_at, p.is_premium,
               p.visibility, p.read_time, p.duration, p.status, COUNT(DISTINCT l.id) AS likes, 
               COUNT(DISTINCT c.id) AS comments, p.views
             FROM posts p
             LEFT JOIN likes l ON p.id = l.post_id
             LEFT JOIN comments c ON p.id = c.post_id
             WHERE p.user_id = $1 AND p.visibility = 'public' AND p.is_draft = FALSE AND p.expires_at > NOW() AND p.status IN ('pending', 'approved')
             GROUP BY p.id, p.views
             ORDER BY p.created_at DESC
             LIMIT 20`,
            [creator.id]
        );

        let subscriptionStatus = null;
        let subscriptionDebug = null;
        if (userId) {
            const subResult = await pool.query(
                `SELECT plan, end_date, amount, payment_method, payment_status
                 FROM subscriptions
                 WHERE user_id = $1 AND creator_id = $2 AND end_date > CURRENT_DATE AND payment_status = 'completed'`,
                [userId, creator.id]
            );
            if (subResult.rowCount > 0) {
                subscriptionStatus = {
                    plan: subResult.rows[0].plan,
                    daysLeft: Math.ceil((new Date(subResult.rows[0].end_date) - new Date()) / (1000 * 60 * 60 * 24)),
                    amount: subResult.rows[0].amount,
                    payment_method: subResult.rows[0].payment_method,
                    payment_status: subResult.rows[0].payment_status
                };
            } else if (process.env.NODE_ENV === 'development') {
                subscriptionDebug = {
                    userId: userId,
                    creatorId: creator.id,
                    rowCount: subResult.rowCount,
                    rows: subResult.rows
                };
            }
        }

        const stats = {
            posts: postsResult.rowCount,
            subscribers: Math.floor(Math.random() * 50000),
            views: postsResult.rows.reduce((sum, post) => sum + (parseInt(post.views) || 0), 0)
        };

        const response = {
            creator: {
                id: creator.id,
                name: creator.name,
                bio: creator.bio || "",
                categories: creator.categories || [],
                profileImage: creator.profile_image || "https://placehold.co/200x200",
                socials: creator.socials || {}
            },
            posts: postsResult.rows.map(post => ({
                id: post.id,
                type: post.type,
                title: post.title,
                caption: post.caption,
                tags: post.tags,
                images: post.images,
                video_url: post.video_url,
                audio_url: post.audio_url,
                created_at: post.created_at,
                isPremium: post.is_premium,
                read_time: post.read_time,
                duration: post.duration,
                likes: parseInt(post.likes) || 0,
                comments: parseInt(post.comments) || 0,
                views: parseInt(post.views) || 0
            })),
            stats,
            subscriptionStatus
        };

        if (subscriptionDebug) {
            response.subscriptionDebug = subscriptionDebug;
        }

        res.json(response);
    } catch (error) {
        console.error("Creator fetch error:", error);
        res.status(500).json({ error: "Failed to fetch creator profile", details: error.message });
    }
});

// Get Subscription Tiers Endpoint
app.get("/creators/:creatorId/subscription-tiers", authenticateToken, async (req, res) => {
    const { creatorId } = req.params;
    try {
        const creatorResult = await pool.query(
            "SELECT user_id FROM creators_page WHERE user_id = $1",
            [creatorId]
        );
        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ error: "Creator not found" });
        }
        const tiersResult = await pool.query(
            `SELECT id, name, price, interval, description, features
             FROM subscription_tiers
             WHERE creator_id = $1`,
            [creatorId]
        );
        const tiers = tiersResult.rows.map((tier) => ({
            id: tier.id,
            name: tier.name,
            price: parseFloat(tier.price),
            interval: tier.interval,
            description: tier.description,
            features: tier.features,
        }));
        res.status(200).json({ tiers });
    } catch (error) {
        console.error("[subscription-tiers] Error:", error);
        res.status(500).json({
            error: "Failed to fetch subscription tiers",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined,
        });
    }
});

app.put("/creators/:creatorId/subscription-tiers/:tierId", authenticateToken, async (req, res) => {
    const { creatorId, tierId } = req.params;
    const { price } = req.body;
    const userId = req.user.id;

    try {
        // Validate creatorId and user ownership
        if (parseInt(creatorId) !== userId) {
            return res.status(403).json({ error: "Unauthorized: You can only update your own tiers" });
        }
        if (isNaN(creatorId) || isNaN(tierId)) {
            return res.status(400).json({ error: "Invalid creator or tier ID" });
        }

        // Validate price
        const parsedPrice = parseFloat(price);
        if (isNaN(parsedPrice) || parsedPrice < 1) {
            return res.status(400).json({ error: "Price must be at least 1 KES" });
        }

        // Verify tier exists and is Monthly or Daily
        const tierResult = await pool.query(
            `SELECT interval FROM subscription_tiers WHERE id = $1 AND creator_id = $2`,
            [tierId, creatorId]
        );
        if (tierResult.rowCount === 0) {
            return res.status(404).json({ error: "Tier not found or not owned by creator" });
        }
        const tier = tierResult.rows[0];
        if (!['month', 'day'].includes(tier.interval)) {
            return res.status(400).json({ error: "Only Monthly or Daily tiers can be updated" });
        }

        // Update only price
        const result = await pool.query(
            `UPDATE subscription_tiers
             SET price = $1, updated_at = CURRENT_TIMESTAMP
             WHERE id = $2 AND creator_id = $3
             RETURNING id, name, price, interval, description, features`,
            [parsedPrice, tierId, creatorId]
        );

        res.json({ message: "Tier price updated successfully", tier: result.rows[0] });
    } catch (error) {
        console.error("Error updating subscription tier:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Fetch User Subscriptions
app.get("/subscriptions", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                s.creator_id,
                u.name AS creator_name,
                cp.profile_image AS avatar_url,
                s.plan,
                s.end_date - CURRENT_DATE AS days_left,
                s.amount,
                s.payment_method,
                s.payment_status
            FROM subscriptions s
            JOIN users u ON s.creator_id = u.id
            LEFT JOIN creators_page cp ON u.id = cp.user_id
            WHERE s.user_id = $1 AND s.end_date > CURRENT_DATE AND s.payment_status = 'completed'
            ORDER BY s.end_date DESC
        `, [req.user.id]);
        res.json(result.rows);
    } catch (error) {
        console.error("Subscriptions fetch error:", error);
        res.status(500).json({ error: "Failed to fetch subscriptions", details: error.message });
    }
});

// Fetch Subscriber Count for a Creator (Public)
app.get("/creators/:creatorId/subscriber-count", async (req, res) => {
    const { creatorId } = req.params;

    try {
        // Validate creatorId
        if (isNaN(creatorId)) {
            return res.status(400).json({ error: "Invalid creator ID" });
        }

        // Verify creator exists
        const creatorResult = await pool.query(
            `SELECT id FROM users u JOIN creators_page cp ON u.id = cp.user_id WHERE u.id = $1`,
            [creatorId]
        );
        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ error: "Creator not found" });
        }

        // Query to count active subscribers
        const result = await pool.query(
            `SELECT COUNT(*) AS count
             FROM subscriptions
             WHERE creator_id = $1 
             AND end_date > CURRENT_DATE 
             AND payment_status = 'completed'`,
            [creatorId]
        );

        res.json({ subscriberCount: parseInt(result.rows[0].count) });
    } catch (error) {
        console.error("Subscriber count fetch error:", error);
        res.status(500).json({ error: "Failed to fetch subscriber count", details: error.message });
    }
});

// Fetch Total Likes, Comments, Views, Revenue, and Subscribers for a Creator
app.get("/creators/:creatorId/stats", authenticateToken, async (req, res) => {
    const { creatorId } = req.params;
    const userId = req.user.id;

    try {
        // Validate creatorId
        if (isNaN(creatorId)) {
            return res.status(400).json({ error: "Invalid creator ID" });
        }

        // Ensure the authenticated user is the creator
        if (parseInt(creatorId) !== userId) {
            return res.status(403).json({ error: "Unauthorized: You can only view your own stats" });
        }

        // Verify creator exists
        const creatorResult = await pool.query(
            `SELECT id FROM users u JOIN creators_page cp ON u.id = cp.user_id WHERE u.id = $1`,
            [creatorId]
        );
        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ error: "Creator not found" });
        }

        // Query to aggregate likes, comments, views, revenue, and subscribers
        const statsQuery = `
            SELECT 
                COALESCE(SUM(p.views), 0) AS total_views,
                COALESCE(COUNT(DISTINCT l.id), 0) AS total_likes,
                COALESCE(COUNT(DISTINCT c.id), 0) AS total_comments,
                COALESCE(SUM(CASE WHEN s.payment_status = 'completed' THEN s.amount ELSE 0 END), 0) AS total_revenue,
                COALESCE(COUNT(DISTINCT CASE WHEN s.payment_status = 'completed' AND s.end_date > CURRENT_DATE THEN s.user_id ELSE NULL END), 0) AS total_subscribers
            FROM posts p
            LEFT JOIN likes l ON p.id = l.post_id
            LEFT JOIN comments c ON p.id = c.post_id
            LEFT JOIN subscriptions s ON s.creator_id = p.user_id
            WHERE p.user_id = $1 
                AND p.visibility = 'public' 
                AND p.is_draft = FALSE 
                AND p.expires_at > NOW()
                AND p.status IN ('pending', 'approved')
            GROUP BY p.user_id
        `;
        const statsResult = await pool.query(statsQuery, [creatorId]);

        // Extract the aggregated stats
        const stats = {
            totalSubscribers: parseInt(statsResult.rows[0].total_subscribers) || 0,
            totalViews: parseInt(statsResult.rows[0].total_views) || 0,
            totalLikes: parseInt(statsResult.rows[0].total_likes) || 0,
            totalComments: parseInt(statsResult.rows[0].total_comments) || 0,
            totalRevenue: parseFloat(statsResult.rows[0].total_revenue) || 0
        };

        // Respond with the stats
        res.json({ stats });
    } catch (error) {
        console.error("Creator stats fetch error:", error);
        res.status(500).json({ error: "Failed to fetch creator stats", details: error.message });
    }
});

// Fetch Total Likes, Comments, and Views for a Specific Post
app.get("/posts/:postId/stats", async (req, res) => {
    const postId = parseInt(req.params.postId);

    try {
        // Validate postId
        if (isNaN(postId)) {
            return res.status(400).json({ error: "Invalid post ID" });
        }

        // Query to aggregate likes, comments, and views
        const statsQuery = `
            SELECT 
                COALESCE(p.views, 0) AS total_views,
                COALESCE(COUNT(DISTINCT l.id), 0) AS total_likes,
                COALESCE(COUNT(DISTINCT c.id), 0) AS total_comments
            FROM posts p
            LEFT JOIN likes l ON p.id = l.post_id
            LEFT JOIN comments c ON p.id = c.post_id
            WHERE p.id = $1 
                AND p.visibility = 'public' 
                AND p.is_draft = FALSE 
                AND p.expires_at > NOW() 
                AND p.status IN ('pending', 'approved')
            GROUP BY p.id, p.views
        `;
        const statsResult = await pool.query(statsQuery, [postId]);

        if (statsResult.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        // Extract the aggregated stats
        const stats = {
            totalLikes: parseInt(statsResult.rows[0].total_likes) || 0,
            totalComments: parseInt(statsResult.rows[0].total_comments) || 0,
            totalViews: parseInt(statsResult.rows[0].total_views) || 0
        };

        // Respond with the stats
        res.json({ stats });
    } catch (error) {
        console.error("Post stats fetch error:", error);
        res.status(500).json({ error: "Failed to fetch post stats", details: error.message });
    }
});

// Fetch Active Subscribers for a Creator
app.get("/creators/:creatorId/subscribers", authenticateToken, async (req, res) => {
    const { creatorId } = req.params;
    const userId = req.user.id;

    try {
        // Ensure the authenticated user is the creator
        if (parseInt(creatorId) !== userId) {
            return res.status(403).json({ error: "Unauthorized: You can only view your own subscribers" });
        }

        // Validate creatorId
        if (isNaN(creatorId)) {
            return res.status(400).json({ error: "Invalid creator ID" });
        }

        // Query to fetch active subscribers
        const result = await pool.query(`
            SELECT 
                s.user_id,
                u.name AS subscriber_name,
                cp.profile_image AS avatar_url,
                s.plan,
                s.start_date,
                s.end_date - CURRENT_DATE AS days_left,
                s.amount,
                s.payment_method,
                s.payment_status
            FROM subscriptions s
            JOIN users u ON s.user_id = u.id
            LEFT JOIN creators_page cp ON u.id = cp.user_id
            WHERE s.creator_id = $1 
                AND s.end_date > CURRENT_DATE 
                AND s.payment_status = 'completed'
            ORDER BY s.end_date DESC
        `, [creatorId]);

        res.json(result.rows);
    } catch (error) {
        console.error("Subscribers fetch error:", error);
        res.status(500).json({ error: "Failed to fetch subscribers", details: error.message });
    }
});
// Toggle Bookmark on Post
app.post("/posts/:id/bookmark", authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.id);
    const userId = req.user.id;

    try {
        const postResult = await pool.query(
            "SELECT id FROM posts WHERE id = $1 AND visibility = 'public' AND is_draft = FALSE AND expires_at > NOW()",
            [postId]
        );
        if (postResult.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        const bookmarkResult = await pool.query(
            "SELECT id FROM bookmarks WHERE user_id = $1 AND post_id = $2",
            [userId, postId]
        );

        if (bookmarkResult.rowCount > 0) {
            await pool.query(
                "DELETE FROM bookmarks WHERE user_id = $1 AND post_id = $2",
                [userId, postId]
            );
            res.json({ message: "Post unbookmarked", isBookmarked: false });
        } else {
            await pool.query(
                "INSERT INTO bookmarks (user_id, post_id) VALUES ($1, $2)",
                [userId, postId]
            );
            res.json({ message: "Post bookmarked", isBookmarked: true });
        }
    } catch (error) {
        console.error("Bookmark toggle error:", error);
        if (error.code === "23505") {
            return res.status(400).json({ error: "Bookmark already exists" });
        }
        res.status(500).json({ error: "Failed to toggle bookmark", details: error.message });
    }
});

// Track Share Action on Post
app.post("/posts/:id/share", authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.id);
    const userId = req.user.id;

    try {
        const postResult = await pool.query(
            "SELECT id, shares FROM posts WHERE id = $1 AND visibility = 'public' AND is_draft = FALSE AND expires_at > NOW()",
            [postId]
        );
        if (postResult.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        const newShares = (postResult.rows[0].shares || 0) + 1;
        await pool.query(
            "UPDATE posts SET shares = $1 WHERE id = $2",
            [newShares, postId]
        );

        res.json({ message: "Post shared", shares: newShares });
    } catch (error) {
        console.error("Share action error:", error);
        res.status(500).json({ error: "Failed to share post", details: error.message });
    }
});

// Fetch Bookmarked Posts
app.get("/bookmarks", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { limit = "20", offset = "0" } = req.query;

    const parsedLimit = parseInt(limit);
    const parsedOffset = parseInt(offset);
    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
        return res.status(400).json({ error: "Limit must be between 1 and 100" });
    }
    if (isNaN(parsedOffset) || parsedOffset < 0) {
        return res.status(400).json({ error: "Offset must be non-negative" });
    }

    try {
        const query = `
            SELECT 
                p.id, p.user_id AS creator_id, p.type, p.title, p.caption, array_to_json(p.tags) AS tags,
                p.images, p.video_url, p.audio_url, p.created_at, p.is_premium, p.visibility,
                p.read_time, p.duration, u.name AS creator_name, cp.profile_image AS creator_avatar,
                COUNT(DISTINCT l.id) AS likes, COUNT(DISTINCT c.id) AS comments,
                p.views,
                TRUE AS is_bookmarked,
                MAX(b.created_at) AS bookmark_created_at
            FROM bookmarks b
            JOIN posts p ON b.post_id = p.id
            LEFT JOIN users u ON p.user_id = u.id
            LEFT JOIN creators_page cp ON p.user_id = cp.user_id
            LEFT JOIN likes l ON p.id = l.post_id
            LEFT JOIN comments c ON p.id = c.post_id
            WHERE b.user_id = $1 AND p.visibility = 'public' AND p.is_draft = FALSE AND p.expires_at > NOW()
            GROUP BY p.id, p.user_id, u.name, cp.profile_image, p.views
            ORDER BY bookmark_created_at DESC
            LIMIT $2 OFFSET $3
        `;
        const result = await pool.query(query, [userId, parsedLimit, parsedOffset]);

        const posts = result.rows.map(post => ({
            id: post.id,
            creatorId: post.creator_id,
            type: post.type,
            title: post.title,
            caption: post.caption,
            tags: post.tags,
            images: post.images,
            video_url: post.video_url,
            audio_url: post.audio_url,
            created_at: post.created_at,
            isPremium: post.is_premium,
            visibility: post.visibility,
            creatorName: post.creator_name,
            creatorAvatar: post.creator_avatar || "https://placehold.co/40x40",
            likes: parseInt(post.likes) || 0,
            comments: parseInt(post.comments) || 0,
            views: parseInt(post.views) || 0,
            duration: post.duration,
            read_time: post.read_time,
            isLiked: false,
            isBookmarked: post.is_bookmarked
        }));

        const totalQuery = `
            SELECT COUNT(*) 
            FROM bookmarks b
            JOIN posts p ON b.post_id = p.id
            WHERE b.user_id = $1 AND p.visibility = 'public' AND p.is_draft = FALSE AND p.expires_at > NOW()
        `;
        const totalResult = await pool.query(totalQuery, [userId]);

        res.json({
            posts,
            pagination: {
                limit: parsedLimit,
                offset: parsedOffset,
                total: parseInt(totalResult.rows[0].count)
            }
        });
    } catch (error) {
        console.error("Bookmarks fetch error:", error);
        res.status(500).json({ error: "Failed to fetch bookmarked posts", details: error.message });
    }
});

// Fetch Moderators
app.get("/moderators", async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT user_moderation_id, name FROM users WHERE user_moderation_id IS NOT NULL ORDER BY name"
        );
        res.json({ moderators: result.rows });
    } catch (error) {
        console.error("Fetch moderators error:", error);
        res.status(500).json({ error: "Failed to fetch moderators", details: error.message });
    }
});

// Report a Post
app.post("/posts/:postId/report", authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.postId);
    const userId = req.user.id;
    const { creatorId, reason, message, timestamp } = req.body;

    try {
        // Validate inputs
        if (isNaN(postId)) {
            return res.status(400).json({ error: "Invalid post ID" });
        }
        if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
            return res.status(400).json({ error: "Reason is required" });
        }
        const validReasons = ["spam", "harassment", "inappropriate", "copyright", "hate_speech", "privacy", "other"];
        if (!validReasons.includes(reason.trim().toLowerCase())) {
            return res.status(400).json({ error: "Invalid reason. Must be one of: " + validReasons.join(", ") });
        }
        if (!timestamp || isNaN(Date.parse(timestamp))) {
            return res.status(400).json({ error: "Invalid timestamp" });
        }
        if (message && (typeof message !== 'string' || message.length > 500)) {
            return res.status(400).json({ error: "Message cannot exceed 500 characters" });
        }
        if (!creatorId || isNaN(creatorId)) {
            return res.status(400).json({ error: "Invalid creator ID" });
        }

        // Verify post exists and is accessible
        const postResult = await pool.query(
            "SELECT id, user_id FROM posts WHERE id = $1 AND visibility = 'public' AND is_draft = FALSE AND expires_at > NOW()",
            [postId]
        );
        if (postResult.rowCount === 0) {
            return res.status(404).json({ error: "Post not found or not accessible" });
        }

        // Verify creatorId matches post's user_id
        if (parseInt(postResult.rows[0].user_id) !== parseInt(creatorId)) {
            return res.status(400).json({ error: "Creator ID does not match post" });
        }

        // Check for duplicate report
        const reportResult = await pool.query(
            "SELECT id FROM reports WHERE post_id = $1 AND reporter_id = $2",
            [postId, userId]
        );
        if (reportResult.rowCount > 0) {
            return res.status(403).json({ error: "You have already reported this post" });
        }

        // Sanitize message
        const sanitizedMessage = message ? message.trim() : null;

        // Insert report
        const result = await pool.query(
            `INSERT INTO reports (post_id, creator_id, reporter_id, reason, message, timestamp, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, post_id, creator_id, reporter_id, reason, message, timestamp, status, created_at`,
            [postId, creatorId, userId, reason.trim().toLowerCase(), sanitizedMessage, timestamp, 'pending']
        );

        const report = result.rows[0];

        // TODO: Add to moderation queue (e.g., Redis, RabbitMQ)
        console.log(`Report ${report.id} queued for moderation: Post ID ${postId}, Reason: ${reason}`);

        res.status(201).json({
            message: "Report submitted successfully",
            reportId: report.id
        });
    } catch (error) {
        console.error("Report submission error:", error);
        if (error.code === "23505") {
            return res.status(403).json({ error: "You have already reported this post" });
        }
        if (error.code === "23503") {
            return res.status(400).json({ error: "Invalid post or creator ID" });
        }
        res.status(500).json({
            error: "Failed to submit report",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// New endpoint: Fetch Earnings Data
app.get("/creators/:creatorId/earnings", authenticateToken, async (req, res) => {
    const { creatorId } = req.params;
    const userId = req.user.id;

    try {
        // Validate creatorId
        if (isNaN(creatorId)) {
            return res.status(400).json({ error: "Invalid creator ID" });
        }

        // Ensure the authenticated user is the creator
        if (parseInt(creatorId) !== userId) {
            return res.status(403).json({ error: "Unauthorized: You can only view your own earnings" });
        }

        // Verify creator exists
        const creatorResult = await pool.query(
            `SELECT id FROM users u JOIN creators_page cp ON u.id = cp.user_id WHERE u.id = $1`,
            [creatorId]
        );
        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ error: "Creator not found" });
        }

        // Query earnings data
        const earningsQuery = `
            SELECT 
                COALESCE(SUM(CASE WHEN t.type = 'subscription' AND t.status = 'completed' THEN t.amount ELSE 0 END), 0) AS total_earnings,
                COALESCE(SUM(CASE WHEN t.type = 'subscription' AND t.status = 'completed' AND NOT EXISTS (
                    SELECT 1 FROM transactions p WHERE p.type = 'payout' AND p.status = 'completed' AND p.created_at >= t.created_at
                ) THEN t.amount ELSE 0 END), 0) AS pending_payout,
                (SELECT t.amount FROM transactions t WHERE t.creator_id = $1 AND t.type = 'payout' AND t.status = 'completed' 
                 ORDER BY t.created_at DESC LIMIT 1) AS last_payout,
                (SELECT t.created_at FROM transactions t WHERE t.creator_id = $1 AND t.type = 'payout' AND t.status = 'completed' 
                 ORDER BY t.created_at DESC LIMIT 1) AS last_payout_date
            FROM transactions t
            WHERE t.creator_id = $1
        `;
        const earningsResult = await pool.query(earningsQuery, [creatorId]);

        // Query transaction history
        const transactionsQuery = `
            SELECT 
                t.created_at AS date,
                t.type,
                t.description,
                t.amount,
                t.status
            FROM transactions t
            WHERE t.creator_id = $1
            ORDER BY t.created_at DESC
            LIMIT 50
        `;
        const transactionsResult = await pool.query(transactionsQuery, [creatorId]);

        // Format response
        const response = {
            totalEarnings: parseFloat(earningsResult.rows[0].total_earnings) || 0,
            pendingPayout: parseFloat(earningsResult.rows[0].pending_payout) || 0,
            lastPayout: parseFloat(earningsResult.rows[0].last_payout) || 0,
            lastPayoutDate: earningsResult.rows[0].last_payout_date ? earningsResult.rows[0].last_payout_date.toISOString() : null,
            transactions: transactionsResult.rows.map(t => ({
                date: t.date.toISOString(),
                type: t.type.charAt(0).toUpperCase() + t.type.slice(1),
                description: t.description,
                amount: parseFloat(t.amount),
                status: t.status.charAt(0).toUpperCase() + t.status.slice(1)
            }))
        };

        res.json(response);
    } catch (error) {
        console.error("Earnings fetch error:", error);
        res.status(500).json({ error: "Failed to fetch earnings data", details: error.message });
    }
});

// Request Payout
app.post("/creators/:creatorId/payouts/request", authenticateToken, async (req, res) => {
    const { creatorId } = req.params;
    const userId = req.user.id;
    const { amount } = req.body;

    try {
        console.log(`➡️ Payout request received: creatorId=${creatorId}, amount=${amount}`);

        // Validate creatorId
        if (isNaN(creatorId)) {
            console.error('Invalid creator ID:', creatorId);
            return res.status(400).json({ error: "Invalid creator ID" });
        }

        // Ensure the authenticated user is the creator
        if (parseInt(creatorId) !== userId) {
            console.error('Unauthorized access: userId=', userId, 'creatorId=', creatorId);
            return res.status(403).json({ error: "Unauthorized: You can only request payouts for yourself" });
        }

        // Verify creator exists
        const creatorResult = await pool.query(
            `SELECT id FROM users u JOIN creators_page cp ON u.id = cp.user_id WHERE u.id = $1`,
            [creatorId]
        );
        if (creatorResult.rowCount === 0) {
            console.error('Creator not found:', creatorId);
            return res.status(404).json({ error: "Creator not found" });
        }

        // Validate amount
        const parsedAmount = parseInt(amount, 10);
        if (isNaN(parsedAmount) || parsedAmount <= 0) {
            console.error('Invalid payout amount:', amount);
            return res.status(400).json({ error: "Invalid payout amount" });
        }

        // Check payout settings
        const settingsResult = await pool.query(
            `SELECT payment_method, payout_threshold, mpesa_phone FROM payout_settings WHERE creator_id = $1`,
            [creatorId]
        );
        const settings = settingsResult.rows[0] || { payout_threshold: 50, payment_method: 'mpesa', mpesa_phone: null };
        if (parsedAmount < settings.payout_threshold) {
            console.error(`Payout amount ${parsedAmount} below threshold ${settings.payout_threshold}`);
            return res.status(400).json({ error: `Payout amount must be at least KES ${settings.payout_threshold}` });
        }

        // Check pending payout balance
        const balanceQuery = `
            SELECT COALESCE(SUM(CASE WHEN t.type = 'subscription' AND t.status = 'completed' AND NOT EXISTS (
                SELECT 1 FROM transactions p WHERE p.type = 'payout' AND p.status = 'completed' AND p.created_at >= t.created_at
            ) THEN t.amount ELSE 0 END), 0) AS pending_payout
            FROM transactions t
            WHERE t.creator_id = $1
        `;
        const balanceResult = await pool.query(balanceQuery, [creatorId]);
        const pendingPayout = parseInt(balanceResult.rows[0].pending_payout, 10) || 0;
        if (parsedAmount > pendingPayout) {
            console.error(`Requested amount ${parsedAmount} exceeds pending balance ${pendingPayout}`);
            return res.status(400).json({ error: "Requested amount exceeds available balance" });
        }

        // Start transaction
        await pool.query("BEGIN");

        // Insert pending payout transaction
        const payoutTransactionId = `PAYOUT-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
        const insertResult = await pool.query(
            `INSERT INTO transactions (creator_id, type, amount, status, transaction_id, description, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id`,
            [
                creatorId,
                'payout',
                -parsedAmount, // Negative for payout
                'pending',
                payoutTransactionId,
                `Payout request to ${settings.payment_method}`
            ]
        );
        const transactionDbId = insertResult.rows[0].id;
        console.log(`✅ Payout transaction created: ID=${payoutTransactionId}, DB ID=${transactionDbId}`);

        // Process payout based on method
        if (settings.payment_method === 'mpesa') {
            if (!settings.mpesa_phone || !/^254\d{9}$/.test(settings.mpesa_phone)) {
                console.error('Invalid M-Pesa phone:', settings.mpesa_phone);
                await pool.query("ROLLBACK");
                return res.status(400).json({ error: "Invalid or missing M-Pesa phone number in settings (must be in 254XXXXXXXXX format)" });
            }

            console.log('🔐 Fetching M-Pesa access token...');
            const token = await getAccessToken();
            console.log('✅ Access token acquired:', token);

            console.log('🔑 Generating security credential...');
            const securityCredential = env.SECURITY_CREDENTIAL; // Assume this is pre-generated and stored securely
            console.log('✅ Security credential generated');

            const b2cEndpoint = process.env.MPESA_ENV === 'sandbox'
                ? 'https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest'
                : 'https://api.safaricom.co.ke/mpesa/b2c/v1/paymentrequest';

            const payload = {
                InitiatorName: process.env.MPESA_INITIATOR_NAME,
                SecurityCredential: securityCredential,
                CommandID: 'BusinessPayment',
                Amount: parsedAmount,
                PartyA: process.env.PAYBILL_NUMBER,
                PartyB: settings.mpesa_phone,
                Remarks: `Payout for creator ID ${creatorId}`,
                QueueTimeOutURL: process.env.MPESA_B2C_TIMEOUT_URL,
                ResultURL: process.env.MPESA_B2C_CALLBACK_URL,
                Occasion: ''
            };
            console.log('📤 B2C Payload:', JSON.stringify(payload, null, 2));

            const response = await axios.post(b2cEndpoint, payload, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            console.log('📥 B2C Response:', JSON.stringify(response.data, null, 2));

            if (response.data.ResponseCode !== '0') {
                console.error('M-Pesa B2C request failed:', response.data.ResponseDescription);
                await pool.query(
                    "UPDATE transactions SET status = 'failed', description = $1 WHERE id = $2",
                    [`Payout failed: ${response.data.ResponseDescription}`, transactionDbId]
                );
                await pool.query("COMMIT");
                return res.status(500).json({ error: "M-Pesa B2C request failed", details: response.data.ResponseDescription });
            }

            // Update transaction with M-Pesa OriginatorConversationID
            await pool.query(
                "UPDATE transactions SET transaction_id = $1 WHERE id = $2",
                [response.data.OriginatorConversationID, transactionDbId]
            );
            console.log(`✅ M-Pesa B2C payout initiated: OriginatorConversationID=${response.data.OriginatorConversationID}`);
        } else {
            console.error(`Payout method '${settings.payment_method}' not supported`);
            await pool.query("ROLLBACK");
            return res.status(501).json({ error: `Payout method '${settings.payment_method}' not yet supported` });
        }

        await pool.query("COMMIT");
        console.log(`✅ Payout request completed: transactionId=${payoutTransactionId}`);

        res.status(201).json({ message: "Payout requested successfully", transactionId: payoutTransactionId });
    } catch (error) {
        await pool.query("ROLLBACK");
        console.error("Payout request error:", error.message, error.stack);
        res.status(500).json({ error: "Failed to request payout", details: error.message });
    }
});

// B2C Callback Endpoint
app.post("/api/mpesa/b2c_callback", async (req, res) => {
    try {
        console.log('📥 Received B2C callback:', JSON.stringify(req.body, null, 2));
        const result = req.body.Body?.Result;
        if (!result || typeof result.ResultCode === 'undefined') {
            console.error("Invalid B2C callback structure:", JSON.stringify(req.body, null, 2));
            return res.status(400).json({ error: "Invalid callback data" });
        }

        const { ResultCode, ResultDesc, OriginatorConversationID, TransactionID } = result;
        const status = ResultCode === '0' ? 'completed' : 'failed';

        // Find the transaction by OriginatorConversationID
        const transResult = await pool.query(
            "SELECT id, creator_id, amount FROM transactions WHERE transaction_id = $1 AND type = 'payout' AND status = 'pending'",
            [OriginatorConversationID]
        );
        if (transResult.rowCount === 0) {
            console.error("No matching pending payout transaction for OriginatorConversationID:", OriginatorConversationID);
            return res.status(404).json({ error: "Transaction not found" });
        }

        const transactionId = transResult.rows[0].id;

        // Update transaction status and M-Pesa TransactionID
        await pool.query(
            "UPDATE transactions SET status = $1, transaction_id = $2, description = $3 WHERE id = $4",
            [status, TransactionID || OriginatorConversationID, `Payout ${status}: ${ResultDesc}`, transactionId]
        );

        console.log(`✅ B2C payout ${status} for transaction ID ${transactionId}: ${ResultDesc}`);

        res.sendStatus(200);
    } catch (error) {
        console.error("B2C callback processing error:", error.message, error.stack);
        res.status(500).json({ error: "Failed to process callback" });
    }
});

// New endpoint: Update Payout Settingss
app.put("/creators/:creatorId/payout-settings", authenticateToken, async (req, res) => {
    const { creatorId } = req.params;
    const userId = req.user.id;
    const { payment_method, payout_threshold, email_notifications, mpesa_phone } = req.body;

    try {
        // Validate creatorId
        if (isNaN(creatorId)) {
            return res.status(400).json({ error: "Invalid creator ID" });
        }

        // Ensure the authenticated user is the creator
        if (parseInt(creatorId) !== userId) {
            return res.status(403).json({ error: "Unauthorized: You can only update your own payout settings" });
        }

        // Verify creator exists
        const creatorResult = await pool.query(
            `SELECT id FROM users u JOIN creators_page cp ON u.id = cp.user_id WHERE u.id = $1`,
            [creatorId]
        );
        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ error: "Creator not found" });
        }

        // Validate inputs
        const validMethods = ['mpesa', 'bank', 'paypal', 'stripe'];
        if (!validMethods.includes(payment_method)) {
            return res.status(400).json({ error: "Invalid payment method" });
        }
        const parsedThreshold = parseInt(payout_threshold, 10);
        if (isNaN(parsedThreshold) || parsedThreshold < 1) {
            return res.status(400).json({ error: "Payout threshold must be at least KES 1" });
        }
        if (typeof email_notifications !== 'boolean') {
            return res.status(400).json({ error: "Email notifications must be a boolean" });
        }
        if (payment_method === 'mpesa') {
            if (!mpesa_phone || !/^254\d{9}$/.test(mpesa_phone)) {
                return res.status(400).json({ error: "Invalid or missing M-Pesa phone number (must be in 254XXXXXXXXX format)" });
            }
        }

        // Upsert payout settings
        const result = await pool.query(
            `INSERT INTO payout_settings (creator_id, payment_method, payout_threshold, email_notifications, mpesa_phone)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (creator_id)
             DO UPDATE SET payment_method = $2, payout_threshold = $3, email_notifications = $4, mpesa_phone = $5
             RETURNING *`,
            [creatorId, payment_method, parsedThreshold, email_notifications, payment_method === 'mpesa' ? mpesa_phone : null]
        );

        res.json({ message: "Payout settings updated", settings: result.rows[0] });
    } catch (error) {
        console.error("Payout settings update error:", error);
        res.status(500).json({ error: "Failed to update payout settings", details: error.message });
    }
});

// New endpoint: Export Transaction History
app.get("/creators/:creatorId/transactions/export", authenticateToken, async (req, res) => {
    const { creatorId } = req.params;
    const userId = req.user.id;

    try {
        // Validate creatorId
        if (isNaN(creatorId)) {
            return res.status(400).json({ error: "Invalid creator ID" });
        }

        // Ensure the authenticated user is the creator
        if (parseInt(creatorId) !== userId) {
            return res.status(403).json({ error: "Unauthorized: You can only export your own transactions" });
        }

        // Verify creator exists
        const creatorResult = await pool.query(
            `SELECT id FROM users u JOIN creators_page cp ON u.id = cp.user_id WHERE u.id = $1`,
            [creatorId]
        );
        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ error: "Creator not found" });
        }

        // Fetch transactions
        const transactionsQuery = `
            SELECT 
                t.created_at AS date,
                t.type,
                t.description,
                t.amount,
                t.status
            FROM transactions t
            WHERE t.creator_id = $1
            ORDER BY t.created_at DESC
        `;
        const transactionsResult = await pool.query(transactionsQuery, [creatorId]);

        // Generate CSV
        const headers = ['Date', 'Type', 'Description', 'Amount', 'Status'];
        const rows = transactionsResult.rows.map(t => [
            t.date.toISOString().split('T')[0],
            t.type.charAt(0).toUpperCase() + t.type.slice(1),
            `"${t.description.replace(/"/g, '""')}"`, // Escape quotes
            t.amount.toFixed(2),
            t.status.charAt(0).toUpperCase() + t.status.slice(1)
        ]);
        const csv = [headers.join(','), ...rows.map(row => row.join(','))].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="transactions-${creatorId}-${Date.now()}.csv"`);
        res.send(csv);
    } catch (error) {
        console.error("Transaction export error:", error);
        res.status(500).json({ error: "Failed to export transactions", details: error.message });
    }
});

// app.listen(port, () => {
//     console.log(`🚀 Server running on port ${port}`);
// });

// After create HTTP server if not already (replace app.listen with this)
const server = require('http').createServer(app);
const io = new Server(server, {
    cors: { origin: '*' }  // Adjust for production (e.g., your frontend URL)
});
server.listen(port, () => console.log(`🚀 Server running on port ${port}`));

// Add this before io setup
app.get('/users/search', authenticateToken, async (req, res) => {
    const { query } = req.query;
    if (!query) return res.status(400).json({ error: 'Query required' });
    try {
        const result = await pool.query(
            `SELECT id, name, (SELECT profile_image FROM creators_page WHERE user_id = users.id) AS profile_image 
             FROM users WHERE name ILIKE $1 AND id != $2 LIMIT 10`,
            [`%${query}%`, req.user.id]  // Exclude self
        );
        res.json(result.rows);
    } catch (error) {
        console.error('User search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Socket.io auth middleware (using your JWT)
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication required'));
    jwt.verify(token, secretKey, (err, user) => {
        if (err) return next(new Error('Invalid token'));
        socket.user = user;  // Attach user to socket
        next();
    });
});

// Socket.io connection handler
io.on('connection', (socket) => {
    console.log(`User ${socket.user.id} connected`);
    socket.join(`user:${socket.user.id}`);  // User-specific room for private messages

    // Presence (basic online/offline)
    io.emit('user:online', { userId: socket.user.id });
    socket.on('disconnect', () => {
        io.emit('user:offline', { userId: socket.user.id });
    });

    // Typing indicator
    socket.on('typing', ({ conversationId, isTyping }) => {
        socket.to(`conversation:${conversationId}`).emit('typing', { userId: socket.user.id, isTyping });
    });

    // Send message
    socket.on('send:message', async ({ conversationId, content }) => {
        if (!content.trim()) return socket.emit('error', { message: 'Empty message' });
        const sanitizedContent = xss(content);  // Sanitize

        try {
            // Validate conversation access
            const convoCheck = await pool.query(
                `SELECT id FROM conversations WHERE id = $1 AND (user1_id = $2 OR user2_id = $2)`,
                [conversationId, socket.user.id]
            );
            if (convoCheck.rowCount === 0) throw new Error('Unauthorized access');

            // Insert to DB
            const result = await pool.query(
                `INSERT INTO messages (conversation_id, sender_id, content) VALUES ($1, $2, $3) RETURNING *`,
                [conversationId, socket.user.id, sanitizedContent]
            );
            const message = result.rows[0];

            // Emit to conversation room (both users)
            io.to(`conversation:${conversationId}`).emit('new:message', message);

            // Optional: Send notification to recipient if offline
            // (Integrate with your notifications system here)
        } catch (error) {
            console.error('Send message error:', error);
            socket.emit('error', { message: error.message });
        }
    });

    // Read receipt
    socket.on('read:message', async ({ messageId, conversationId }) => {
        try {
            await pool.query(
                `UPDATE messages SET read_at = NOW(), status = 'read' WHERE id = $1 AND conversation_id = $2`,
                [messageId, conversationId]
            );
            socket.to(`conversation:${conversationId}`).emit('message:read', { messageId });
        } catch (error) {
            console.error('Read receipt error:', error);
        }
    });

    // Join conversation room (called from frontend on chat open)
    socket.on('join:conversation', ({ conversationId }) => {
        socket.join(`conversation:${conversationId}`);
    });
});

// REST Endpoints (for history and starting convos; authenticate with your middleware)

// GET /conversations - Fetch user's conversations with previews
app.get('/conversations', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(`
            SELECT 
                c.id, 
                CASE WHEN c.user1_id = $1 THEN u2.name ELSE u1.name END AS recipient_name,
                CASE WHEN c.user1_id = $1 THEN u2.id ELSE u1.id END AS recipient_id,
                m.content AS last_message,
                m.created_at AS last_message_at
            FROM conversations c
            LEFT JOIN users u1 ON c.user1_id = u1.id
            LEFT JOIN users u2 ON c.user2_id = u2.id
            LEFT JOIN LATERAL (
                SELECT content, created_at FROM messages 
                WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1
            ) m ON true
            WHERE c.user1_id = $1 OR c.user2_id = $1
            ORDER BY COALESCE(m.created_at, c.created_at) DESC
        `, [userId]);
        res.json(result.rows);
    } catch (error) {
        console.error('Fetch conversations error:', error);
        res.status(500).json({ error: 'Failed to fetch conversations' });
    }
});

// GET /conversations/:id/messages - Paginated history
app.get('/conversations/:id/messages', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    const { limit = 50, offset = 0 } = req.query;
    try {
        // Validate access
        const accessCheck = await pool.query(
            `SELECT id FROM conversations WHERE id = $1 AND (user1_id = $2 OR user2_id = $2)`,
            [id, userId]
        );
        if (accessCheck.rowCount === 0) return res.status(403).json({ error: 'Unauthorized' });

        const result = await pool.query(`
            SELECT m.*, u.name AS sender_name 
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.conversation_id = $1
            ORDER BY m.created_at DESC
            LIMIT $2 OFFSET $3
        `, [id, limit, offset]);
        res.json(result.rows);
    } catch (error) {
        console.error('Fetch messages error:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// POST /conversations - Start new conversation (if not exists)
app.post('/conversations', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { recipientId } = req.body;
    if (userId === recipientId) return res.status(400).json({ error: 'Cannot message yourself' });
        // In POST /conversations
try {
    const [user1, user2] = [userId, recipientId].sort((a, b) => a - b);
    const insertResult = await pool.query(`
        INSERT INTO conversations (user1_id, user2_id)
        VALUES ($1, $2)
        ON CONFLICT (user1_id, user2_id) DO NOTHING
        RETURNING id
    `, [user1, user2]);

    let conversationId;
    if (insertResult.rowCount > 0) {
        conversationId = insertResult.rows[0].id;
    } else {
        const selectResult = await pool.query(`
            SELECT id FROM conversations WHERE user1_id = $1 AND user2_id = $2
        `, [user1, user2]);
        if (selectResult.rowCount === 0) throw new Error('Conversation not found after insert attempt');
        conversationId = selectResult.rows[0].id;
    }
    res.json({ conversationId });
} catch (error) {
    console.error('Start conversation error:', error);
    res.status(500).json({ error: 'Failed to start conversation' });
}
});

