import { rateLimit } from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';

// Extend Request interface to include user property
interface AuthenticatedRequest extends Request {
  user?: any;
}

// Rate limiting configurations - more lenient in development
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'development' ? 1000 : 100, // Much higher limit in dev
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: 15 * 60 // seconds
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for development assets
    if (process.env.NODE_ENV === 'development') {
      return req.path.includes('/@fs/') || 
             req.path.includes('/node_modules/') ||
             req.path.includes('.js') ||
             req.path.includes('.css') ||
             req.path.includes('.map') ||
             req.path.includes('/assets/');
    }
    return false;
  }
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 authentication attempts per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.',
    retryAfter: 15 * 60
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
});

export const orderLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // Limit each IP to 10 orders per 5 minutes
  message: {
    error: 'Too many orders placed, please wait before placing another order.',
    retryAfter: 5 * 60
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const posLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 20, // Limit each IP to 20 POS transactions per minute
  message: {
    error: 'Too many POS transactions, please slow down.',
    retryAfter: 60
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Security headers middleware
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  // Remove X-Powered-By header
  res.removeHeader('X-Powered-By');
  
  // Set security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self' ws: wss:; " +
    "frame-ancestors 'none';"
  );
  
  next();
};

// Request sanitization middleware
export const sanitizeInput = (req: Request, res: Response, next: NextFunction) => {
  // Recursively sanitize object properties
  const sanitizeObject = (obj: any): any => {
    if (typeof obj === 'string') {
      // Remove dangerous characters and HTML tags
      return obj
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<[^>]*>/g, '')
        .trim();
    } else if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    } else if (obj && typeof obj === 'object') {
      const sanitized: any = {};
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          sanitized[key] = sanitizeObject(obj[key]);
        }
      }
      return sanitized;
    }
    return obj;
  };

  // Sanitize request body
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }

  // Sanitize query parameters
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }

  next();
};

// Simple CAPTCHA verification (for demo purposes)
export const verifyCaptcha = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const { captcha } = req.body;
  
  // Skip CAPTCHA for authenticated users or specific routes
  if (req.user || req.path.includes('/api/products')) {
    return next();
  }

  // Simple math CAPTCHA verification
  if (req.method === 'POST' && req.path.includes('/register')) {
    if (!captcha || !captcha.answer || !captcha.expected) {
      return res.status(400).json({
        error: 'CAPTCHA verification required',
        captcha: generateMathCaptcha()
      });
    }

    if (parseInt(captcha.answer) !== parseInt(captcha.expected)) {
      return res.status(400).json({
        error: 'CAPTCHA verification failed',
        captcha: generateMathCaptcha()
      });
    }
  }

  next();
};

// Generate simple math CAPTCHA
export const generateMathCaptcha = () => {
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const operations = ['+', '-', '*'];
  const operation = operations[Math.floor(Math.random() * operations.length)];
  
  let expected: number;
  let question: string;
  
  switch (operation) {
    case '+':
      expected = a + b;
      question = `${a} + ${b}`;
      break;
    case '-':
      expected = Math.max(a, b) - Math.min(a, b);
      question = `${Math.max(a, b)} - ${Math.min(a, b)}`;
      break;
    case '*':
      expected = a * b;
      question = `${a} × ${b}`;
      break;
    default:
      expected = a + b;
      question = `${a} + ${b}`;
  }
  
  return {
    question: `What is ${question}?`,
    expected: expected.toString()
  };
};

// IP whitelist for admin actions (in production, use environment variables)
const ADMIN_IP_WHITELIST = [
  '127.0.0.1',
  '::1',
  'localhost'
];

export const adminIPWhitelist = (req: Request, res: Response, next: NextFunction) => {
  // Get the real IP address, considering proxies
  const ip = req.ip || 
             req.connection.remoteAddress || 
             req.socket.remoteAddress ||
             (req.connection as any)?.socket?.remoteAddress ||
             req.headers['x-forwarded-for'] ||
             req.headers['x-real-ip'];

  // In development, allow all IPs
  if (process.env.NODE_ENV === 'development') {
    return next();
  }

  // Check if IP is whitelisted for admin operations
  if (req.path.includes('/admin') && !ADMIN_IP_WHITELIST.includes(ip as string)) {
    return res.status(403).json({
      error: 'Access denied: IP not authorized for admin operations'
    });
  }

  next();
};

// Request logging middleware
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  const timestamp = new Date().toISOString();
  
  // Log request
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
  
  // Log response on finish
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${timestamp}] ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
  });

  next();
};

// File upload security (if implementing file uploads later)
export const fileUploadSecurity = {
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max file size
    files: 1 // Max 1 file per request
  },
  allowedMimeTypes: [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'application/pdf'
  ],
  sanitizeFilename: (filename: string) => {
    return filename
      .replace(/[^a-zA-Z0-9\-_\.]/g, '')
      .substring(0, 100); // Limit filename length
  }
};

