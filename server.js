const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
const { body, validationResult } = require('express-validator');
const archiver = require('archiver');
const fsExtra = require('fs-extra');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const crypto = require('crypto');
require('dotenv').config();

// Create DOMPurify instance
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const app = express();
const PORT = process.env.PORT || 1337;

// Security Configuration
const isDevelopment = process.env.NODE_ENV === 'development';

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: !isDevelopment,
}));

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001', 
      'http://localhost:3002',
      'http://localhost:3003',
      'http://localhost:3004',
      'http://127.0.0.1:3000',
      process.env.FRONTEND_URL
    ].filter(Boolean);
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all origins in development
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Length', 'X-Content-Type-Options'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration - temporarily disabled for debugging
// app.use(session({
//   store: new SQLiteStore({
//     db: 'sessions.db',
//     dir: './data'
//   }),
//   secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
//   resave: false,
//   saveUninitialized: false,
//   cookie: {
//     secure: !isDevelopment, // HTTPS only in production
//     httpOnly: true,
//     maxAge: 24 * 60 * 60 * 1000, // 24 hours
//     sameSite: 'strict'
//   }
// }));

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
  message: 'Zu viele Login-Versuche, bitte versuchen Sie es später erneut.',
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Zu viele Anfragen, bitte versuchen Sie es später erneut.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting to all requests
app.use('/api/', generalLimiter);

// Serve uploads with security headers
app.use('/uploads', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'");
  next();
}, express.static('uploads'));

// Prevent access to sensitive directories
app.use('/data', (req, res) => res.status(403).send('Forbidden'));
app.use('/backups', (req, res) => res.status(403).send('Forbidden'));
app.use('/.git', (req, res) => res.status(403).send('Forbidden'));
app.use('/.env', (req, res) => res.status(403).send('Forbidden'));

// Create uploads directory if not exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Database setup
const db = new sqlite3.Database('./data/feuerwehr.db');

// Create tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'editor',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reset_token TEXT,
    reset_token_expires DATETIME
  )`);

  // Articles table
  db.run(`CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    summary TEXT,
    content TEXT NOT NULL,
    image TEXT,
    author_id INTEGER,
    published BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users (id)
  )`);

  // Events table
  db.run(`CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    date DATE NOT NULL,
    time TEXT,
    location TEXT,
    description TEXT,
    image TEXT,
    attachments TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Pages table for static content
  db.run(`CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    is_visible BOOLEAN DEFAULT 1,
    order_index INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Menu items table
  db.run(`CREATE TABLE IF NOT EXISTS menu_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    parent_id INTEGER,
    order_index INTEGER DEFAULT 0,
    is_visible BOOLEAN DEFAULT 1,
    target TEXT DEFAULT '_self',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Settings table
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Gallery table
  db.run(`CREATE TABLE IF NOT EXISTS gallery (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    image TEXT NOT NULL,
    category TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Members table for board members
  db.run(`CREATE TABLE IF NOT EXISTS board_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    position TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    image TEXT,
    order_index INTEGER DEFAULT 0,
    active BOOLEAN DEFAULT 1
  )`);

  // Club statistics table
  db.run(`CREATE TABLE IF NOT EXISTS club_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    label TEXT NOT NULL,
    unit TEXT,
    order_index INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Contact messages table
  db.run(`CREATE TABLE IF NOT EXISTS contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT DEFAULT 'new',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Membership applications table
  db.run(`CREATE TABLE IF NOT EXISTS membership_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    street TEXT NOT NULL,
    postal_code TEXT NOT NULL,
    city TEXT NOT NULL,
    birth_date TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Media library table
  db.run(`CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER,
    url TEXT NOT NULL,
    alt_text TEXT,
    folder TEXT DEFAULT 'general',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Newsletter subscribers
  db.run(`CREATE TABLE IF NOT EXISTS newsletter_subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    status TEXT DEFAULT 'active',
    subscribed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    unsubscribed_at DATETIME
  )`);

  // Newsletter campaigns
  db.run(`CREATE TABLE IF NOT EXISTS newsletter_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT NOT NULL,
    content TEXT NOT NULL,
    sent_at DATETIME,
    sent_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Form builder
  db.run(`CREATE TABLE IF NOT EXISTS forms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    fields TEXT NOT NULL,
    settings TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Form submissions
  db.run(`CREATE TABLE IF NOT EXISTS form_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    form_id INTEGER NOT NULL,
    data TEXT NOT NULL,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (form_id) REFERENCES forms (id)
  )`);

  // Page builder blocks
  db.run(`CREATE TABLE IF NOT EXISTS page_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER,
    block_type TEXT NOT NULL,
    content TEXT NOT NULL,
    settings TEXT,
    order_index INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (page_id) REFERENCES pages (id)
  )`);

  // Backups
  db.run(`CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    size INTEGER,
    type TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Audit logs
  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT,
    resource_id INTEGER,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Help articles
  db.run(`CREATE TABLE IF NOT EXISTS help_articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    category TEXT,
    video_url TEXT,
    order_index INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Create default admin user if not exists
  // Generate a random password on first run
  const defaultPassword = process.env.ADMIN_DEFAULT_PASSWORD || crypto.randomBytes(16).toString('hex');
  const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  const adminPassword = bcrypt.hashSync(defaultPassword, bcryptRounds);
  
  db.get(`SELECT id FROM users WHERE username = 'admin'`, (err, row) => {
    if (!row) {
      db.run(`INSERT INTO users (username, email, password, role) 
              VALUES ('admin', ?, ?, 'admin')`, 
              [process.env.ADMIN_EMAIL || 'admin@ff-oberstaufenbach.de', adminPassword],
              function(err) {
                if (!err) {
                  console.log('=================================');
                  console.log('ADMIN ACCOUNT CREATED');
                  console.log('Username: admin');
                  console.log('Password:', defaultPassword);
                  console.log('PLEASE CHANGE THIS PASSWORD IMMEDIATELY!');
                  console.log('=================================');
                }
              });
    }
  });

  // Initialize default statistics if not exists
  const defaultStats = [
    { key: 'years_tradition', value: '40', label: 'Jahre Tradition', unit: '+', order_index: 1 },
    { key: 'active_members', value: '200', label: 'Aktive Mitglieder', unit: '+', order_index: 2 },
    { key: 'yearly_funding', value: '50000', label: 'Jährliche Förderung', unit: '€', order_index: 3 },
    { key: 'availability', value: '24/7', label: 'Einsatzbereit', unit: '', order_index: 4 },
    { key: 'membership_fee', value: '25', label: 'Jahresbeitrag', unit: '€', order_index: 5 }
  ];

  defaultStats.forEach(stat => {
    db.run(`INSERT OR IGNORE INTO club_statistics (key, value, label, unit, order_index) VALUES (?, ?, ?, ?, ?)`,
      [stat.key, stat.value, stat.label, stat.unit, stat.order_index]);
  });
  
  // Insert default settings
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('site_title', 'Feuerwehrförderverein Oberstaufenbach')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('contact_email', 'info@ff-oberstaufenbach.de')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('membership_fee', '25')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('member_count', '150')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('form_membership_fee', '25')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('form_membership_text', 'Der Jahresbeitrag beträgt nur')`);
  
  // Email settings
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_host', 'smtp.gmail.com')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_port', '587')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_user', '')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_pass', '')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_from', 'noreply@ff-oberstaufenbach.de')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('email_notifications', 'true')`);
  
  // Insert default pages
  db.run(`INSERT OR IGNORE INTO pages (slug, title, content) VALUES ('about', 'Über uns', 
    'Der Feuerwehrförderverein Oberstaufenbach wurde gegründet, um die Freiwillige Feuerwehr Oberstaufenbach in ihrer wichtigen Arbeit zu unterstützen.')`);
  db.run(`INSERT OR IGNORE INTO pages (slug, title, content) VALUES ('contact', 'Kontakt', 
    'Feuerwehrförderverein Oberstaufenbach\nVorsitzender: Max Mustermann\nTelefon: 06781 / 12345\nE-Mail: info@ff-oberstaufenbach.de')`);
  db.run(`INSERT OR IGNORE INTO pages (slug, title, content) VALUES ('imprint', 'Impressum', 
    'Angaben gemäß § 5 TMG\n\nFeuerwehrförderverein Oberstaufenbach e.V.\nMusterstraße 1\n55765 Birkenfeld')`);
  db.run(`INSERT OR IGNORE INTO pages (slug, title, content) VALUES ('privacy', 'Datenschutz', 
    'Datenschutzerklärung\n\nDer Schutz Ihrer persönlichen Daten ist uns ein besonderes Anliegen.')`);
  db.run(`INSERT OR IGNORE INTO pages (slug, title, content) VALUES ('membership', 'Mitgliedschaft', 
    'Warum Mitglied werden?\n\nAls Mitglied des Feuerwehrfördervereins Oberstaufenbach leisten Sie einen wichtigen Beitrag zur Sicherheit unserer Gemeinde. Ihre Unterstützung ermöglicht es uns, die Freiwillige Feuerwehr bei ihrer lebensrettenden Arbeit zu fördern.\n\nIhre Vorteile als Mitglied:\n• Regelmäßige Informationen über die Aktivitäten der Feuerwehr\n• Einladungen zu exklusiven Mitgliederveranstaltungen\n• Mitspracherecht bei der Mitgliederversammlung\n• Das gute Gefühl, einen wichtigen Beitrag zu leisten\n\nVerwendung der Mitgliedsbeiträge:\n• Anschaffung von Ausrüstung und Geräten\n• Unterstützung der Jugendfeuerwehr\n• Finanzierung von Aus- und Weiterbildungen\n• Modernisierung des Feuerwehrhauses\n\nJahresbeitrag:\nDer Jahresbeitrag beträgt nur 25,00 €.\n\nBeitritt:\nFüllen Sie das Online-Formular aus oder laden Sie unser PDF-Formular herunter.')`);
});

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const uploadImage = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Nur Bilder sind erlaubt'));
    }
  }
});

const uploadDocs = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|doc|docx|xls|xlsx|jpg|jpeg|png/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    
    if (extname) {
      return cb(null, true);
    } else {
      cb(new Error('Dateityp nicht erlaubt'));
    }
  }
});

// PDF upload specifically for membership form
const uploadPDF = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const extname = path.extname(file.originalname).toLowerCase() === '.pdf';
    const mimetype = file.mimetype === 'application/pdf';
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Nur PDF-Dateien sind erlaubt!'));
    }
  }
});

// Helper function for audit logging
const logAudit = (userId, action, resource, resourceId, details, req) => {
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  
  db.run(
    `INSERT INTO audit_logs (user_id, action, resource, resource_id, details, ip_address, user_agent) 
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, action, resource, resourceId, JSON.stringify(details), ipAddress, userAgent]
  );
};

// Sanitize HTML content
const sanitizeHtml = (html) => {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
                   'blockquote', 'code', 'pre', 'ol', 'ul', 'li', 'a', 'img', 'table', 
                   'thead', 'tbody', 'tr', 'td', 'th', 'div', 'span', 'hr', 'strike',
                   'sub', 'sup', 'video', 'iframe'],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'class', 'style', 'target', 'width', 'height',
                   'align', 'border', 'frameborder', 'allowfullscreen'],
    ALLOWED_SCHEMES: ['http', 'https', 'mailto'],
    ALLOW_DATA_ATTR: false
  });
};

// Sanitize plain text (removes all HTML)
const sanitizeText = (text) => {
  if (!text) return '';
  return text.replace(/<[^>]*>/g, '').trim();
};

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    // Check if user still exists and is not locked
    db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, dbUser) => {
      if (err || !dbUser) {
        return res.status(403).json({ error: 'User not found' });
      }
      
      if (dbUser.locked_until && new Date(dbUser.locked_until) > new Date()) {
        return res.status(403).json({ error: 'Account is locked' });
      }
      
      req.user = user;
      next();
    });
  });
};

// Routes

// Auth routes with improved security
app.post('/api/auth/login', loginLimiter, [
  body('username').trim().isLength({ min: 3, max: 50 }).escape(),
  body('password').isLength({ min: 6, max: 100 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;
  const maxLoginAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
  const lockoutDuration = parseInt(process.env.LOGIN_LOCKOUT_DURATION) || 15; // minutes

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (!user) {
      // Don't reveal if username exists
      logAudit(null, 'LOGIN_FAILED', 'users', null, { username }, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      logAudit(user.id, 'LOGIN_ATTEMPT_WHILE_LOCKED', 'users', user.id, { username }, req);
      return res.status(401).json({ error: 'Account is temporarily locked' });
    }

    try {
      const isValidPassword = await bcrypt.compare(password, user.password);
      
      if (!isValidPassword) {
        // Increment login attempts
        const newAttempts = (user.login_attempts || 0) + 1;
        let lockedUntil = null;
        
        if (newAttempts >= maxLoginAttempts) {
          lockedUntil = new Date(Date.now() + lockoutDuration * 60 * 1000).toISOString();
          logAudit(user.id, 'ACCOUNT_LOCKED', 'users', user.id, { attempts: newAttempts }, req);
        }
        
        db.run(
          'UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?',
          [newAttempts, lockedUntil, user.id]
        );
        
        logAudit(user.id, 'LOGIN_FAILED', 'users', user.id, { attempts: newAttempts }, req);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Reset login attempts and update last login
      db.run(
        'UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?',
        [user.id]
      );

      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Don't send password hash in response
      const userResponse = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      };
      
      logAudit(user.id, 'LOGIN_SUCCESS', 'users', user.id, {}, req);
      
      res.json({ 
        token, 
        user: userResponse,
        expiresIn: 86400 // 24 hours in seconds
      });
      
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
});

// Change password endpoint
app.post('/api/auth/change-password', authenticateToken, [
  body('currentPassword').isLength({ min: 6 }),
  body('newPassword').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least 8 characters, including uppercase, lowercase, number and special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { currentPassword, newPassword } = req.body;
  
  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
    if (err || !user) {
      return res.status(500).json({ error: 'User not found' });
    }
    
    try {
      const isValidPassword = await bcrypt.compare(currentPassword, user.password);
      if (!isValidPassword) {
        logAudit(req.user.id, 'PASSWORD_CHANGE_FAILED', 'users', req.user.id, { reason: 'invalid_current' }, req);
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      
      const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);
      
      db.run(
        'UPDATE users SET password = ?, password_changed_at = CURRENT_TIMESTAMP WHERE id = ?',
        [hashedPassword, req.user.id],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to update password' });
          }
          
          logAudit(req.user.id, 'PASSWORD_CHANGED', 'users', req.user.id, {}, req);
          res.json({ message: 'Password changed successfully' });
        }
      );
    } catch (error) {
      console.error('Password change error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
});

// Articles routes
app.get('/api/articles', (req, res) => {
  const query = req.query.published === 'true' 
    ? 'SELECT * FROM articles WHERE published = 1 ORDER BY created_at DESC'
    : 'SELECT * FROM articles ORDER BY created_at DESC';
    
  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/api/articles/:slug', (req, res) => {
  db.get('SELECT * FROM articles WHERE slug = ?', [req.params.slug], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Article not found' });
    }
    res.json(row);
  });
});

app.post('/api/articles', authenticateToken, uploadImage.single('image'), (req, res) => {
  const { title, summary, content, published } = req.body;
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  db.run(
    `INSERT INTO articles (title, slug, summary, content, image, author_id, published) 
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [title, slug, summary, content, image, req.user.id, published || 0],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, title, slug, summary, content, image, published });
    }
  );
});

app.put('/api/articles/:id', authenticateToken, uploadImage.single('image'), (req, res) => {
  const { title, summary, content, published } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : req.body.existingImage;

  db.run(
    `UPDATE articles SET title = ?, summary = ?, content = ?, image = ?, published = ?, updated_at = CURRENT_TIMESTAMP 
     WHERE id = ?`,
    [title, summary, content, image, published || 0, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Article updated' });
    }
  );
});

app.delete('/api/articles/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM articles WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Article deleted' });
  });
});

// Events routes
app.get('/api/events', (req, res) => {
  db.all('SELECT * FROM events ORDER BY date ASC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/api/events/:id', (req, res) => {
  db.get('SELECT * FROM events WHERE id = ?', [req.params.id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Event not found' });
    }
    res.json(row);
  });
});

app.post('/api/events', authenticateToken, uploadDocs.fields([
  { name: 'image', maxCount: 1 },
  { name: 'attachments', maxCount: 5 }
]), (req, res) => {
  const { title, date, time, location, description } = req.body;
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  
  const image = req.files['image'] ? `/uploads/${req.files['image'][0].filename}` : null;
  const attachments = req.files['attachments'] 
    ? req.files['attachments'].map(file => `/uploads/${file.filename}`).join(',')
    : null;

  db.run(
    `INSERT INTO events (title, slug, date, time, location, description, image, attachments) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [title, slug, date, time, location, description, image, attachments],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, title, slug, date, time, location, description, image, attachments });
    }
  );
});

app.put('/api/events/:id', authenticateToken, uploadDocs.fields([
  { name: 'image', maxCount: 1 },
  { name: 'attachments', maxCount: 5 }
]), (req, res) => {
  const { title, date, time, location, description } = req.body;
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  
  let image = req.body.existingImage || null;
  let attachments = req.body.existingAttachments || null;
  
  if (req.files['image']) {
    image = `/uploads/${req.files['image'][0].filename}`;
  }
  
  if (req.files['attachments']) {
    const newAttachments = req.files['attachments'].map(file => `/uploads/${file.filename}`).join(',');
    attachments = attachments ? `${attachments},${newAttachments}` : newAttachments;
  }

  db.run(
    `UPDATE events SET title = ?, slug = ?, date = ?, time = ?, location = ?, description = ?, image = ?, attachments = ?, updated_at = CURRENT_TIMESTAMP 
     WHERE id = ?`,
    [title, slug, date, time, location, description, image, attachments, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Event updated' });
    }
  );
});

app.delete('/api/events/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM events WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Event deleted' });
  });
});

// Pages routes
app.get('/api/pages', (req, res) => {
  db.all('SELECT * FROM pages', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/api/pages/:slug', (req, res) => {
  db.get('SELECT * FROM pages WHERE slug = ?', [req.params.slug], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Page not found' });
    }
    res.json(row);
  });
});

app.put('/api/pages/:slug', authenticateToken, [
  body('title').trim().isLength({ min: 1, max: 200 }).escape(),
  body('content').trim().isLength({ min: 1 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { title, content } = req.body;
  
  // Sanitize HTML content to prevent XSS
  const sanitizedContent = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
                   'blockquote', 'code', 'pre', 'ol', 'ul', 'li', 'a', 'img', 'table', 
                   'thead', 'tbody', 'tr', 'td', 'th', 'div', 'span', 'hr', 'strike',
                   'sub', 'sup', 'video', 'iframe'],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'class', 'style', 'target', 'width', 'height',
                   'align', 'border', 'frameborder', 'allowfullscreen'],
    ALLOWED_SCHEMES: ['http', 'https', 'mailto'],
    ALLOW_DATA_ATTR: false
  });
  
  db.run(
    `UPDATE pages SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?`,
    [title, sanitizedContent, req.params.slug],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Page not found' });
      }
      res.json({ message: 'Page updated', changes: this.changes });
    }
  );
});

// Create new page
app.post('/api/pages', authenticateToken, [
  body('title').trim().isLength({ min: 1, max: 200 }).escape(),
  body('slug').trim().isLength({ min: 1, max: 100 }).matches(/^[a-z0-9-]+$/),
  body('content').trim().isLength({ min: 1 }),
  body('is_visible').optional().isBoolean(),
  body('order_index').optional().isNumeric()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { title, slug, content, is_visible = 1, order_index = 0 } = req.body;
  
  // Check if slug already exists
  db.get('SELECT id FROM pages WHERE slug = ?', [slug], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (row) {
      return res.status(409).json({ error: 'A page with this slug already exists' });
    }
    
    // Sanitize HTML content
    const sanitizedContent = DOMPurify.sanitize(content, {
      ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
                     'blockquote', 'code', 'pre', 'ol', 'ul', 'li', 'a', 'img', 'table', 
                     'thead', 'tbody', 'tr', 'td', 'th', 'div', 'span', 'hr', 'strike',
                     'sub', 'sup', 'video', 'iframe'],
      ALLOWED_ATTR: ['href', 'src', 'alt', 'class', 'style', 'target', 'width', 'height',
                     'align', 'border', 'frameborder', 'allowfullscreen'],
      ALLOWED_SCHEMES: ['http', 'https', 'mailto'],
      ALLOW_DATA_ATTR: false
    });
    
    // Insert new page
    db.run(
      `INSERT INTO pages (slug, title, content, is_visible, order_index) VALUES (?, ?, ?, ?, ?)`,
      [slug, title, sanitizedContent, is_visible, order_index],
      function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ 
          id: this.lastID, 
          slug, 
          title, 
          content: sanitizedContent, 
          is_visible, 
          order_index 
        });
      }
    );
  });
});

// Delete page
app.delete('/api/pages/:id', authenticateToken, (req, res) => {
  const pageId = req.params.id;
  
  // Don't allow deletion of core pages
  db.get('SELECT slug FROM pages WHERE id = ?', [pageId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Page not found' });
    }
    
    const protectedSlugs = ['about', 'contact', 'membership', 'privacy', 'imprint'];
    if (protectedSlugs.includes(row.slug)) {
      return res.status(403).json({ error: 'Cannot delete protected pages' });
    }
    
    // Delete the page
    db.run('DELETE FROM pages WHERE id = ?', [pageId], function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      // Also remove from menu if exists
      db.run('DELETE FROM menu_items WHERE url = ?', [`/${row.slug}`], (err) => {
        // Ignore menu deletion errors
      });
      
      res.json({ message: 'Page deleted successfully' });
    });
  });
});

// Settings routes
app.get('/api/settings', (req, res) => {
  db.all('SELECT * FROM settings', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.put('/api/settings', authenticateToken, (req, res) => {
  const updates = req.body;
  const errors = [];
  let completed = 0;
  
  Object.keys(updates).forEach(key => {
    db.run(
      `INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
      [key, updates[key]],
      function(err) {
        if (err) {
          errors.push({ key, error: err.message });
        }
        completed++;
        
        if (completed === Object.keys(updates).length) {
          if (errors.length > 0) {
            res.status(500).json({ errors });
          } else {
            res.json({ message: 'Settings updated' });
          }
        }
      }
    );
  });
});

// Gallery routes
app.get('/api/gallery', (req, res) => {
  db.all('SELECT * FROM gallery ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/gallery', authenticateToken, uploadImage.single('image'), (req, res) => {
  const { title, description, category } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;
  
  if (!image) {
    return res.status(400).json({ error: 'Image is required' });
  }
  
  db.run(
    `INSERT INTO gallery (title, description, image, category) VALUES (?, ?, ?, ?)`,
    [title, description || '', image, category || 'general'],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, title, description, image, category });
    }
  );
});

app.delete('/api/gallery/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM gallery WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Gallery item deleted' });
  });
});

// Board members routes
app.get('/api/board-members', (req, res) => {
  db.all('SELECT * FROM board_members WHERE active = 1 ORDER BY order_index, id', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/board-members', authenticateToken, uploadImage.single('image'), (req, res) => {
  const { name, position, email, phone, order_index } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;
  
  db.run(
    `INSERT INTO board_members (name, position, email, phone, image, order_index) 
     VALUES (?, ?, ?, ?, ?, ?)`,
    [name, position, email || '', phone || '', image, order_index || 0],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, name, position, email, phone, image, order_index });
    }
  );
});

app.put('/api/board-members/:id', authenticateToken, uploadImage.single('image'), (req, res) => {
  const { name, position, email, phone, order_index, active } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : req.body.existingImage;
  
  db.run(
    `UPDATE board_members SET name = ?, position = ?, email = ?, phone = ?, image = ?, 
     order_index = ?, active = ? WHERE id = ?`,
    [name, position, email || '', phone || '', image, order_index || 0, active || 1, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Board member updated' });
    }
  );
});

app.delete('/api/board-members/:id', authenticateToken, (req, res) => {
  db.run('UPDATE board_members SET active = 0 WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Board member deactivated' });
  });
});

// Email helper function
async function sendEmail(to, subject, html) {
  try {
    // Get email settings from database
    const settings = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM settings WHERE key LIKE "smtp_%" OR key = "email_notifications"', (err, rows) => {
        if (err) reject(err);
        const settingsObj = {};
        rows.forEach(row => {
          settingsObj[row.key] = row.value;
        });
        resolve(settingsObj);
      });
    });

    if (settings.email_notifications !== 'true') {
      console.log('Email notifications disabled');
      return;
    }

    if (!settings.smtp_user || !settings.smtp_pass) {
      console.log('SMTP credentials not configured');
      return;
    }

    // Create transporter
    const transporter = nodemailer.createTransport({
      host: settings.smtp_host,
      port: parseInt(settings.smtp_port),
      secure: false,
      auth: {
        user: settings.smtp_user,
        pass: settings.smtp_pass
      }
    });

    // Send email
    await transporter.sendMail({
      from: settings.smtp_from || 'noreply@ff-oberstaufenbach.de',
      to,
      subject,
      html
    });

    console.log('Email sent successfully to:', to);
  } catch (error) {
    console.error('Error sending email:', error);
  }
}

// Contact form endpoint
app.post('/api/contact', async (req, res) => {
  const { first_name, last_name, email, phone, subject, message } = req.body;

  try {
    // Save to database
    db.run(
      `INSERT INTO contact_messages (first_name, last_name, email, phone, subject, message) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [first_name, last_name, email, phone, subject, message],
      async function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        // Get contact email from settings
        db.get('SELECT value FROM settings WHERE key = "contact_email"', async (err, row) => {
          if (!err && row) {
            // Send email notification
            const emailHtml = `
              <h2>Neue Kontaktanfrage</h2>
              <p><strong>Von:</strong> ${first_name} ${last_name}</p>
              <p><strong>E-Mail:</strong> ${email}</p>
              <p><strong>Telefon:</strong> ${phone || 'Nicht angegeben'}</p>
              <p><strong>Betreff:</strong> ${subject}</p>
              <p><strong>Nachricht:</strong></p>
              <p>${message.replace(/\n/g, '<br>')}</p>
            `;

            await sendEmail(row.value, `Neue Kontaktanfrage: ${subject}`, emailHtml);
          }
        });

        res.json({ 
          success: true, 
          message: 'Ihre Nachricht wurde erfolgreich gesendet!' 
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Fehler beim Senden der Nachricht' });
  }
});

// Membership application endpoint
app.post('/api/membership', async (req, res) => {
  const { 
    first_name, 
    last_name, 
    email, 
    phone, 
    street, 
    postal_code, 
    city, 
    birth_date 
  } = req.body;

  try {
    // Save to database
    db.run(
      `INSERT INTO membership_applications 
       (first_name, last_name, email, phone, street, postal_code, city, birth_date) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [first_name, last_name, email, phone, street, postal_code, city, birth_date],
      async function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        // Get contact email from settings
        db.get('SELECT value FROM settings WHERE key = "contact_email"', async (err, row) => {
          if (!err && row) {
            // Send email notification
            const emailHtml = `
              <h2>Neuer Mitgliedsantrag</h2>
              <p><strong>Name:</strong> ${first_name} ${last_name}</p>
              <p><strong>E-Mail:</strong> ${email}</p>
              <p><strong>Telefon:</strong> ${phone || 'Nicht angegeben'}</p>
              <p><strong>Adresse:</strong> ${street}, ${postal_code} ${city}</p>
              <p><strong>Geburtsdatum:</strong> ${birth_date || 'Nicht angegeben'}</p>
            `;

            await sendEmail(row.value, 'Neuer Mitgliedsantrag', emailHtml);
          }
        });

        res.json({ 
          success: true, 
          message: 'Ihr Mitgliedsantrag wurde erfolgreich übermittelt!' 
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Fehler beim Senden des Antrags' });
  }
});

// Get contact messages (admin only)
app.get('/api/contact-messages', authenticateToken, (req, res) => {
  db.all('SELECT * FROM contact_messages ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Update contact message status
app.put('/api/contact-messages/:id', authenticateToken, (req, res) => {
  const { status } = req.body;
  
  db.run(
    'UPDATE contact_messages SET status = ? WHERE id = ?',
    [status, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Status updated' });
    }
  );
});

// Get membership applications (admin only)
app.get('/api/membership-applications', authenticateToken, (req, res) => {
  db.all('SELECT * FROM membership_applications ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Update membership application status
app.put('/api/membership-applications/:id', authenticateToken, (req, res) => {
  const { status } = req.body;
  
  db.run(
    'UPDATE membership_applications SET status = ? WHERE id = ?',
    [status, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Status updated' });
    }
  );
});

// Menu items routes
app.get('/api/menu-items', (req, res) => {
  db.all('SELECT * FROM menu_items ORDER BY order_index', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/menu-items', authenticateToken, (req, res) => {
  const { title, url, parent_id, order_index, target } = req.body;
  
  db.run(
    `INSERT INTO menu_items (title, url, parent_id, order_index, target) VALUES (?, ?, ?, ?, ?)`,
    [title, url, parent_id || null, order_index || 0, target || '_self'],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, ...req.body });
    }
  );
});

app.put('/api/menu-items/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  const fields = Object.keys(updates);
  const values = Object.values(updates);
  
  const setClause = fields.map(field => `${field} = ?`).join(', ');
  
  db.run(
    `UPDATE menu_items SET ${setClause} WHERE id = ?`,
    [...values, id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Menu item updated' });
    }
  );
});

app.put('/api/menu-items/reorder', authenticateToken, (req, res) => {
  const { items } = req.body;
  
  const stmt = db.prepare('UPDATE menu_items SET order_index = ? WHERE id = ?');
  
  items.forEach((item) => {
    stmt.run(item.order_index, item.id);
  });
  
  stmt.finalize();
  res.json({ message: 'Menu reordered' });
});

app.delete('/api/menu-items/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM menu_items WHERE id = ?', [id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Menu item deleted' });
  });
});

// Upload membership form PDF
app.post('/api/upload-membership-pdf', authenticateToken, uploadPDF.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Keine PDF-Datei hochgeladen' });
    }

    const pdfPath = `/uploads/${req.file.filename}`;

    // Save PDF path to settings
    db.run(
      `INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`,
      ['membership_form_pdf', pdfPath],
      function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ 
          success: true, 
          path: pdfPath,
          message: 'PDF erfolgreich hochgeladen'
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Fehler beim Hochladen der PDF' });
  }
});

// Page blocks routes
app.get('/api/page-blocks/:pageId', (req, res) => {
  const { pageId } = req.params;
  
  db.all('SELECT * FROM page_blocks WHERE page_id = ? ORDER BY order_index', [pageId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows.map(row => ({
      ...row,
      content: JSON.parse(row.content || '{}'),
      settings: JSON.parse(row.settings || '{}')
    })));
  });
});

app.put('/api/page-blocks/:pageId', authenticateToken, (req, res) => {
  const { pageId } = req.params;
  const { blocks } = req.body;
  
  // Delete existing blocks
  db.run('DELETE FROM page_blocks WHERE page_id = ?', [pageId], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    // Insert new blocks
    const stmt = db.prepare('INSERT INTO page_blocks (page_id, block_type, content, settings, order_index) VALUES (?, ?, ?, ?, ?)');
    
    blocks.forEach((block) => {
      stmt.run(
        pageId,
        block.type,
        JSON.stringify(block.content),
        JSON.stringify(block.settings || {}),
        block.order_index
      );
    });
    
    stmt.finalize();
    res.json({ message: 'Blocks saved' });
  });
});

// Media library routes
app.get('/api/media', (req, res) => {
  db.all('SELECT * FROM media ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/media/upload', authenticateToken, uploadImage.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Keine Datei hochgeladen' });
    }

    const { folder = 'general' } = req.body;
    const fileUrl = `/uploads/${req.file.filename}`;

    db.run(
      `INSERT INTO media (filename, original_name, mime_type, size, url, folder) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        req.file.filename,
        req.file.originalname,
        req.file.mimetype,
        req.file.size,
        fileUrl,
        folder
      ],
      function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ 
          id: this.lastID,
          url: fileUrl,
          message: 'Datei erfolgreich hochgeladen'
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Fehler beim Hochladen der Datei' });
  }
});

app.put('/api/media/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { alt_text } = req.body;

  db.run(
    'UPDATE media SET alt_text = ? WHERE id = ?',
    [alt_text, id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Alt-Text aktualisiert' });
    }
  );
});

app.delete('/api/media/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  // Get file info first
  db.get('SELECT filename FROM media WHERE id = ?', [id], (err, row) => {
    if (err || !row) {
      return res.status(404).json({ error: 'Datei nicht gefunden' });
    }

    // Delete file from filesystem
    const filePath = path.join(__dirname, 'uploads', row.filename);
    fs.unlink(filePath, (err) => {
      // Continue even if file doesn't exist on disk
    });

    // Delete from database
    db.run('DELETE FROM media WHERE id = ?', [id], function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Datei gelöscht' });
    });
  });
});

// Backup routes
app.get('/api/backups', authenticateToken, (req, res) => {
  db.all('SELECT * FROM backups ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/backups/create', authenticateToken, async (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
    const filename = `backup-${timestamp}.zip`;
    const backupDir = path.join(__dirname, 'backups');
    const backupPath = path.join(backupDir, filename);
    
    // Create backups directory if it doesn't exist
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true });
    }
    
    // Create a file to stream archive data to
    const output = fs.createWriteStream(backupPath);
    const archive = archiver('zip', {
      zlib: { level: 9 } // Maximum compression
    });
    
    // Listen for close event
    output.on('close', function() {
      const stats = fs.statSync(backupPath);
      
      // Save backup info to database
      db.run(
        'INSERT INTO backups (filename, size, type) VALUES (?, ?, ?)',
        [filename, stats.size, 'full'],
        function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          res.json({
            id: this.lastID,
            filename,
            size: stats.size,
            type: 'full',
            created_at: new Date().toISOString()
          });
        }
      );
    });
    
    // Handle errors
    archive.on('error', function(err) {
      res.status(500).json({ error: err.message });
    });
    
    // Pipe archive data to the file
    archive.pipe(output);
    
    // Add database file
    archive.file('feuerwehr.db', { name: 'database/feuerwehr.db' });
    
    // Add uploads directory
    const uploadsDir = path.join(__dirname, 'uploads');
    if (fs.existsSync(uploadsDir)) {
      archive.directory(uploadsDir, 'uploads');
    }
    
    // Finalize the archive
    archive.finalize();
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/backups/restore/:id', authenticateToken, async (req, res) => {
  const backupId = req.params.id;
  
  db.get('SELECT * FROM backups WHERE id = ?', [backupId], async (err, backup) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!backup) {
      return res.status(404).json({ error: 'Backup not found' });
    }
    
    try {
      const backupPath = path.join(__dirname, 'backups', backup.filename);
      
      if (!fs.existsSync(backupPath)) {
        return res.status(404).json({ error: 'Backup file not found' });
      }
      
      // Extract backup to temp directory
      const tempDir = path.join(__dirname, 'temp-restore');
      await fsExtra.ensureDir(tempDir);
      
      const extract = require('extract-zip');
      await extract(backupPath, { dir: tempDir });
      
      // Close database connection
      db.close();
      
      // Restore database
      const dbPath = path.join(__dirname, 'feuerwehr.db');
      const backupDbPath = path.join(tempDir, 'database', 'feuerwehr.db');
      
      if (fs.existsSync(backupDbPath)) {
        await fsExtra.copy(backupDbPath, dbPath, { overwrite: true });
      }
      
      // Restore uploads
      const uploadsDir = path.join(__dirname, 'uploads');
      const backupUploadsDir = path.join(tempDir, 'uploads');
      
      if (fs.existsSync(backupUploadsDir)) {
        await fsExtra.emptyDir(uploadsDir);
        await fsExtra.copy(backupUploadsDir, uploadsDir);
      }
      
      // Clean up temp directory
      await fsExtra.remove(tempDir);
      
      res.json({ message: 'Backup restored successfully. Please restart the server.' });
      
      // Exit process to force restart
      setTimeout(() => {
        process.exit(0);
      }, 1000);
      
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
});

app.get('/api/backups/download/:id', authenticateToken, (req, res) => {
  const backupId = req.params.id;
  
  db.get('SELECT * FROM backups WHERE id = ?', [backupId], (err, backup) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!backup) {
      return res.status(404).json({ error: 'Backup not found' });
    }
    
    const backupPath = path.join(__dirname, 'backups', backup.filename);
    
    if (!fs.existsSync(backupPath)) {
      return res.status(404).json({ error: 'Backup file not found' });
    }
    
    res.download(backupPath, backup.filename);
  });
});

app.delete('/api/backups/:id', authenticateToken, (req, res) => {
  const backupId = req.params.id;
  
  db.get('SELECT * FROM backups WHERE id = ?', [backupId], (err, backup) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!backup) {
      return res.status(404).json({ error: 'Backup not found' });
    }
    
    const backupPath = path.join(__dirname, 'backups', backup.filename);
    
    // Delete file if exists
    if (fs.existsSync(backupPath)) {
      fs.unlinkSync(backupPath);
    }
    
    // Delete from database
    db.run('DELETE FROM backups WHERE id = ?', [backupId], function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Backup deleted successfully' });
    });
  });
});

// Upload backup
app.post('/api/backups/upload', authenticateToken, (req, res) => {
  const backupDir = path.join(__dirname, 'backups');
  
  // Create custom multer instance for this route
  const backupStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
      }
      cb(null, backupDir);
    },
    filename: (req, file, cb) => {
      // Keep original filename if it's a backup file, otherwise generate new name
      if (file.originalname.startsWith('backup-')) {
        cb(null, file.originalname);
      } else {
        const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
        cb(null, `backup-${timestamp}.zip`);
      }
    }
  });

  const uploadBackup = multer({ 
    storage: backupStorage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
    fileFilter: (req, file, cb) => {
      if (path.extname(file.originalname).toLowerCase() === '.zip') {
        return cb(null, true);
      } else {
        cb(new Error('Nur ZIP-Dateien sind erlaubt'));
      }
    }
  }).single('backup');

  uploadBackup(req, res, function(err) {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    
    if (!req.file) {
      return res.status(400).json({ error: 'Keine Datei hochgeladen' });
    }
    
    const stats = fs.statSync(req.file.path);
    
    // Save backup info to database
    db.run(
      'INSERT INTO backups (filename, size, type) VALUES (?, ?, ?)',
      [req.file.filename, stats.size, 'uploaded'],
      function(err) {
        if (err) {
          // Delete file if database insert fails
          fs.unlinkSync(req.file.path);
          return res.status(500).json({ error: err.message });
        }
        res.json({
          id: this.lastID,
          filename: req.file.filename,
          size: stats.size,
          type: 'uploaded',
          created_at: new Date().toISOString()
        });
      }
    );
  });
});

// Newsletter routes
app.get('/api/newsletter/subscribers', authenticateToken, (req, res) => {
  db.all('SELECT * FROM newsletter_subscribers ORDER BY subscribed_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/newsletter/subscribers', authenticateToken, (req, res) => {
  const { email, name } = req.body;
  
  db.run(
    'INSERT OR IGNORE INTO newsletter_subscribers (email, name) VALUES (?, ?)',
    [email, name || null],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, email, name });
    }
  );
});

app.put('/api/newsletter/subscribers/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  
  const updateData = status === 'unsubscribed' 
    ? { status, unsubscribed_at: new Date().toISOString() }
    : { status, unsubscribed_at: null };
  
  db.run(
    'UPDATE newsletter_subscribers SET status = ?, unsubscribed_at = ? WHERE id = ?',
    [updateData.status, updateData.unsubscribed_at, id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Subscriber updated' });
    }
  );
});

app.get('/api/newsletter/campaigns', authenticateToken, (req, res) => {
  db.all('SELECT * FROM newsletter_campaigns ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/newsletter/send', authenticateToken, async (req, res) => {
  const { subject, content, subscriber_ids } = req.body;
  
  // Get subscribers
  const placeholders = subscriber_ids.map(() => '?').join(',');
  db.all(
    `SELECT * FROM newsletter_subscribers WHERE id IN (${placeholders}) AND status = 'active'`,
    subscriber_ids,
    async (err, subscribers) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      // Save campaign
      db.run(
        'INSERT INTO newsletter_campaigns (subject, content, sent_at, sent_count) VALUES (?, ?, ?, ?)',
        [subject, content, new Date().toISOString(), subscribers.length],
        async function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          
          // Send emails
          for (const subscriber of subscribers) {
            try {
              await sendEmail(
                subscriber.email,
                subject,
                `<html><body>${content}</body></html>`
              );
            } catch (error) {
              console.error(`Failed to send to ${subscriber.email}:`, error);
            }
          }
          
          res.json({ 
            message: 'Newsletter sent successfully',
            sent_count: subscribers.length
          });
        }
      );
    }
  );
});

// Club statistics API
app.get('/api/statistics', (req, res) => {
  db.all('SELECT * FROM club_statistics ORDER BY order_index', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/api/statistics/:key', (req, res) => {
  const { key } = req.params;
  db.get('SELECT * FROM club_statistics WHERE key = ?', [key], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Statistic not found' });
    }
    res.json(row);
  });
});

app.put('/api/statistics/:key', authenticateToken, [
  body('value').notEmpty().trim().escape(),
  body('label').optional().trim().escape(),
  body('unit').optional().trim().escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { key } = req.params;
  const { value, label, unit } = req.body;
  
  const updates = ['value = ?', 'updated_at = CURRENT_TIMESTAMP'];
  const values = [value];
  
  if (label !== undefined) {
    updates.push('label = ?');
    values.push(label);
  }
  
  if (unit !== undefined) {
    updates.push('unit = ?');
    values.push(unit);
  }
  
  values.push(key);
  
  db.run(
    `UPDATE club_statistics SET ${updates.join(', ')} WHERE key = ?`,
    values,
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Statistic not found' });
      }
      
      // Audit log
      logAudit(req.user.id, 'UPDATE_STATISTIC', 'club_statistics', key, { value, label, unit }, req);
      
      res.json({ message: 'Statistic updated successfully' });
    }
  );
});

// Forms API
app.get('/api/forms', authenticateToken, (req, res) => {
  db.all('SELECT * FROM forms ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/forms', authenticateToken, (req, res) => {
  const { name, slug, fields, settings } = req.body;
  
  db.run(
    'INSERT INTO forms (name, slug, fields, settings) VALUES (?, ?, ?, ?)',
    [name, slug, fields, settings || '{}'],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, name, slug, fields, settings });
    }
  );
});

app.put('/api/forms/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { name, slug, fields, settings } = req.body;
  
  db.run(
    'UPDATE forms SET name = ?, slug = ?, fields = ?, settings = ? WHERE id = ?',
    [name, slug, fields, settings, id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Form updated' });
    }
  );
});

app.delete('/api/forms/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM forms WHERE id = ?', [id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Form deleted' });
  });
});

app.get('/api/forms/:id/submissions', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  db.all(
    'SELECT * FROM form_submissions WHERE form_id = ? ORDER BY submitted_at DESC',
    [id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows);
    }
  );
});

// Public form submission endpoint
app.post('/api/forms/:slug/submit', async (req, res) => {
  const { slug } = req.params;
  const data = req.body;
  
  // Get form details
  db.get('SELECT * FROM forms WHERE slug = ?', [slug], async (err, form) => {
    if (err || !form) {
      return res.status(404).json({ error: 'Form not found' });
    }
    
    const settings = JSON.parse(form.settings || '{}');
    
    // Save submission
    db.run(
      'INSERT INTO form_submissions (form_id, data) VALUES (?, ?)',
      [form.id, JSON.stringify(data)],
      async function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        // Send email if configured
        if (settings.emailTo) {
          try {
            const fields = JSON.parse(form.fields);
            let emailContent = `<h2>Neue Formulareinreichung: ${form.name}</h2>`;
            
            fields.forEach((field) => {
              if (data[field.name]) {
                emailContent += `<p><strong>${field.label}:</strong> ${data[field.name]}</p>`;
              }
            });
            
            await sendEmail(
              settings.emailTo,
              settings.emailSubject || `Neue Einreichung: ${form.name}`,
              emailContent
            );
          } catch (error) {
            console.error('Failed to send form email:', error);
          }
        }
        
        res.json({ 
          success: true,
          message: settings.successMessage || 'Formular erfolgreich gesendet!'
        });
      }
    );
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server läuft auf http://localhost:${PORT}`);
  console.log(`Admin-Login: username: admin, password: admin123`);
});