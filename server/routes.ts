import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import { storage } from "./storage";
import { emailService } from "./email-service";
import { loginSchema, insertUserSchema, insertOrderSchema, insertAddressSchema, insertProductSchema, insertPaymentQrCodeSchema } from "./shared/schema";
import { z } from "zod";
import {
  generalLimiter,
  authLimiter,
  orderLimiter,
  posLimiter,
  securityHeaders,
  sanitizeInput,
  requestLogger
} from "./middleware/security";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Middleware to verify JWT
const authenticateToken = async (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    const user = await storage.getUserById(decoded.userId);
    if (!user) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Middleware to check admin role
const requireAdmin = (req: any, res: any, next: any) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);

  // Apply security middleware
  app.use(securityHeaders);
  app.use(sanitizeInput);
  app.use(requestLogger);
  app.use(generalLimiter);

  // Initialize WebSocket server
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });
  const clients = new Map<string, WebSocket>();

  wss.on('connection', (ws: WebSocket, req) => {
    console.log('WebSocket connection established');
    
    ws.on('message', async (data: Buffer) => {
      try {
        const message = JSON.parse(data.toString());
        
        if (message.type === 'auth') {
          const token = message.token;
          try {
            const decoded = jwt.verify(token, JWT_SECRET) as any;
            const user = await storage.getUserById(decoded.userId);
            if (user) {
              clients.set(user.id, ws);
              ws.send(JSON.stringify({ type: 'auth_success', userId: user.id }));
            }
          } catch (error) {
            ws.send(JSON.stringify({ type: 'auth_error', message: 'Invalid token' }));
          }
        }

        if (message.type === 'chat_message') {
          // WebSocket messages are now handled by HTTP API
          // This prevents duplicate message creation
          // Real-time broadcasting is done in the HTTP endpoint
        }

        if (message.type === 'order_update') {
          // Broadcast order update to relevant clients
          const order = await storage.getOrderById(message.orderId);
          if (order) {
            const customerWs = clients.get(order.customerId);
            if (customerWs && customerWs.readyState === WebSocket.OPEN) {
              customerWs.send(JSON.stringify({
                type: 'order_status_update',
                order: order,
              }));
            }
          }
        }
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    });

    ws.on('close', () => {
      // Remove client from map
      for (const [userId, client] of Array.from(clients.entries())) {
        if (client === ws) {
          clients.delete(userId);
          break;
        }
      }
    });
  });

  // Seed data on startup
  try {
    await storage.seedData();
    console.log('Database seeded successfully');
  } catch (error) {
    console.error('Seeding failed:', error);
  }

  // Auth routes
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = loginSchema.parse(req.body);
      console.log('[Login API] Attempting login for email:', email);

      const user = await storage.validateUser(email, password);
      console.log('[Login API] User validation result:', user ? 'Success' : 'Failed');

      if (!user) {
        console.log('[Login API] Invalid credentials for email:', email);
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Check if email is verified
      if (!user.emailVerified) {
        console.log('[Login API] Email not verified for user:', user.email);
        return res.status(403).json({
          message: 'Please verify your email before logging in',
          emailVerified: false,
          email: user.email
        });
      }

      console.log('[Login API] Login successful for user:', user.email);
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

      res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          phone: user.phone,
          address: user.address,
          addressCoordinates: user.addressCoordinates,
          avatar: user.avatar,
          emailVerified: user.emailVerified,
        },
      });
    } catch (error) {
      console.log('[Login API] Error during login:', error);
      res.status(400).json({ message: 'Invalid request data' });
    }
  });

  app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
      const userData = insertUserSchema.parse(req.body);

      // Check if user exists
      const existingUser = await storage.getUserByEmail(userData.email);
      if (existingUser) {
        // Allow re-registration for admin email to grant admin access
        if (userData.email === 'gasflow40@gmail.com') {
          // Update existing user to admin role
          const updatedUser = await storage.updateUser(existingUser.id, { role: 'admin' });
          if (!updatedUser) {
            return res.status(500).json({ message: 'Failed to update user role' });
          }
          return res.status(200).json({
            message: 'Account updated to admin access. Please verify your email if not already done.',
            user: {
              id: updatedUser.id,
              email: updatedUser.email,
              name: updatedUser.name,
              role: updatedUser.role,
              phone: updatedUser.phone,
              avatar: updatedUser.avatar,
              emailVerified: updatedUser.emailVerified,
            },
          });
        }
        return res.status(400).json({ message: 'User already exists' });
      }

      // Grant admin role to specific email
      if (userData.email === 'gasflow40@gmail.com') {
        userData.role = 'admin';
      }

      // Set acceptance fields if privacy policy was accepted
      if (userData.privacyAccepted) {
        (userData as any).privacyAcceptedAt = new Date();
        (userData as any).privacyAccepted = true;
      }

      const user = await storage.createUser(userData);

      // Generate email verification token
      const verificationToken = emailService.generateVerificationToken();
      const tokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Set verification token
      await storage.setEmailVerificationToken(user.id, verificationToken, tokenExpires);

      // Send verification email
      try {
        await emailService.sendVerificationEmail(user.email, verificationToken);
      } catch (emailError) {
        console.error('Failed to send verification email:', emailError);
        // Don't fail registration if email fails, but log it
      }

      res.status(201).json({
        message: 'Registration successful. Please check your email to verify your account.',
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          phone: user.phone,
          avatar: user.avatar,
          emailVerified: user.emailVerified,
        },
      });
    } catch (error) {
      res.status(400).json({ message: 'Invalid request data' });
    }
  });

  app.get('/api/auth/me', authenticateToken, (req: any, res) => {
    res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        role: req.user.role,
        phone: req.user.phone,
        address: req.user.address,
        addressCoordinates: req.user.addressCoordinates,
        avatar: req.user.avatar,
        emailVerified: req.user.emailVerified,
      },
    });
  });

  // Email verification endpoint
  app.get('/api/auth/verify-email', async (req, res) => {
    try {
      const { token } = req.query;

      if (!token || typeof token !== 'string') {
        return res.status(400).json({ message: 'Invalid verification token' });
      }

      const user = await storage.getUserByVerificationToken(token);
      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired verification token' });
      }

      // Mark email as verified
      await storage.updateUserEmailVerification(user.id, true);

      res.json({
        message: 'Email verified successfully! You can now log in to your account.',
        verified: true
      });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({ message: 'Failed to verify email' });
    }
  });

  // Resend verification email
  app.post('/api/auth/resend-verification', authLimiter, async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: 'Email is required' });
      }

      const user = await storage.getUserByEmail(email);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      if (user.emailVerified) {
        return res.status(400).json({ message: 'Email is already verified' });
      }

      // Generate new verification token
      const verificationToken = emailService.generateVerificationToken();
      const tokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Set verification token
      await storage.setEmailVerificationToken(user.id, verificationToken, tokenExpires);

      // Send verification email
      try {
        await emailService.sendVerificationEmail(user.email, verificationToken);
        res.json({ message: 'Verification email sent successfully' });
      } catch (emailError) {
        console.error('Failed to send verification email:', emailError);
        res.status(500).json({ message: 'Failed to send verification email' });
      }
    } catch (error) {
      res.status(500).json({ message: 'Failed to resend verification email' });
    }
  });

  // Change password
  app.put('/api/auth/change-password', authenticateToken, async (req: any, res) => {
    try {
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Current password and new password are required' });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ message: 'New password must be at least 6 characters long' });
      }

      // Verify current password
      const isValid = await bcrypt.compare(currentPassword, req.user.password);
      if (!isValid) {
        return res.status(400).json({ message: 'Current password is incorrect' });
      }

      // Update password (updateUser will hash the password)
      const user = await storage.updateUser(req.user.id, { password: newPassword });

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error('Password change error:', error);
      res.status(500).json({ message: 'Failed to change password' });
    }
  });

  // Request password reset
  app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
    try {
      const { email } = req.body;

      console.log('[Forgot Password API] Request received for email:', email);

      if (!email) {
        console.log('[Forgot Password API] No email provided');
        return res.status(400).json({ message: 'Email is required' });
      }

      const user = await storage.getUserByEmail(email);
      if (!user) {
        console.log('[Forgot Password API] User not found for email:', email);
        // Don't reveal if user exists or not for security
        return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
      }

      console.log('[Forgot Password API] User found, generating reset token');
      // Generate password reset token
      const resetToken = emailService.generatePasswordResetToken();
      const tokenExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      console.log('[Forgot Password API] Setting reset token for user:', user.id);
      // Set password reset token
      await storage.setPasswordResetToken(user.id, resetToken, tokenExpires);

      console.log('[Forgot Password API] Sending reset email to:', user.email);
      // Send password reset email
      try {
        await emailService.sendPasswordResetEmail(user.email, resetToken);
        console.log('[Forgot Password API] Reset email sent successfully');
        res.json({ message: 'Password reset email sent successfully' });
      } catch (emailError) {
        console.error('[Forgot Password API] Failed to send password reset email:', emailError);
        res.status(500).json({ message: 'Failed to send password reset email' });
      }
    } catch (error) {
      console.error('[Forgot Password API] Error processing request:', error);
      res.status(500).json({ message: 'Failed to process password reset request' });
    }
  });

  // Reset password with token
  app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      console.log('[Reset Password API] Received request with token:', token ? 'Present' : 'Missing');

      if (!token || !newPassword) {
        console.log('[Reset Password API] Missing required fields:', { token: !!token, newPassword: !!newPassword });
        return res.status(400).json({ message: 'Token and new password are required' });
      }

      if (newPassword.length < 6) {
        console.log('[Reset Password API] Password too short');
        return res.status(400).json({ message: 'New password must be at least 6 characters long' });
      }

      console.log('[Reset Password API] Looking up user by token');
      const user = await storage.getUserByPasswordResetToken(token);
      console.log('[Reset Password API] User lookup result:', user ? 'Found' : 'Not found');
      if (user) {
        console.log('[Reset Password API] User details:', {
          id: user.id,
          email: user.email,
          tokenExpires: user.passwordResetExpires,
          currentTime: new Date().toISOString()
        });

        // Check if token is expired
        const now = new Date();
        const expires = user.passwordResetExpires ? new Date(user.passwordResetExpires) : null;
        console.log('[Reset Password API] Token expired?', expires ? now > expires : 'No expiration date', 'Now:', now.toISOString(), 'Expires:', expires?.toISOString());
      }
      if (!user) {
        console.log('[Reset Password API] User not found or token invalid/expired');
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      console.log('[Reset Password API] User found, updating password');
      // Update password and clear reset token (updateUser will hash the password)
      const updatedUser = await storage.updateUser(user.id, {
        password: newPassword,
        passwordResetToken: null,
        passwordResetExpires: null
      } as any);

      if (!updatedUser) {
        console.log('[Reset Password API] Failed to update user');
        return res.status(500).json({ message: 'Failed to update user password' });
      }

      console.log('[Reset Password API] Password reset successful for user:', user.email);
      console.log('[Reset Password API] Verifying password was updated correctly');

      // Verify the password was updated by checking it can be validated
      const verifyUser = await storage.validateUser(user.email, newPassword);
      if (!verifyUser) {
        console.log('[Reset Password API] ERROR: Password update verification failed!');
        return res.status(500).json({ message: 'Password update verification failed' });
      }

      console.log('[Reset Password API] Password update verified successfully');
      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error('[Reset Password API] Error:', error);
      res.status(500).json({ message: 'Failed to reset password' });
    }
  });

  // User routes
  app.get('/api/users/addresses', authenticateToken, async (req: any, res) => {
    try {
      const addresses = await storage.getUserAddresses(req.user.id);
      res.json(addresses);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch addresses' });
    }
  });

  app.post('/api/users/addresses', authenticateToken, async (req: any, res) => {
    try {
      const addressData = insertAddressSchema.parse({
        ...req.body,
        userId: req.user.id,
      });
      console.log('[Address Creation] Creating address with data:', {
        userId: req.user.id,
        label: addressData.label,
        street: addressData.street,
        city: addressData.city,
        coordinates: addressData.coordinates,
        hasCoordinates: !!addressData.coordinates
      });
      const address = await storage.createAddress(addressData);
      console.log('[Address Creation] Address created successfully:', {
        id: address.id,
        coordinates: address.coordinates
      });
      res.status(201).json(address);
    } catch (error) {
      console.error('[Address Creation] Error creating address:', error);
      res.status(400).json({ message: 'Invalid address data' });
    }
  });

  app.put('/api/users/addresses/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;

      console.log('[Address Update] User:', req.user.id, 'Address ID:', id, 'Updates:', updates);

      // First check if the address belongs to the user
      const existingAddress = await storage.getUserAddresses(req.user.id);
      const addressExists = existingAddress.find(addr => addr.id === id);

      if (!addressExists) {
        console.log('[Address Update] Address not found or not owned by user');
        return res.status(404).json({ message: 'Address not found or access denied' });
      }

      const address = await storage.updateAddress(id, updates);

      if (!address) {
        console.log('[Address Update] Update failed');
        return res.status(500).json({ message: 'Failed to update address' });
      }

      console.log('[Address Update] Success:', address);
      res.json(address);
    } catch (error) {
      console.error('[Address Update] Error:', error);
      res.status(400).json({ message: 'Failed to update address' });
    }
  });

  app.delete('/api/users/addresses/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;

      console.log('[Address Delete] User:', req.user.id, 'Address ID:', id);

      // First check if the address belongs to the user
      const existingAddresses = await storage.getUserAddresses(req.user.id);
      const addressExists = existingAddresses.find(addr => addr.id === id);

      if (!addressExists) {
        console.log('[Address Delete] Address not found or not owned by user');
        return res.status(404).json({ message: 'Address not found or access denied' });
      }

      // Check if address is used in any orders
      const ordersWithAddress = await storage.getOrdersByCustomer(req.user.id);
      const addressInUse = ordersWithAddress.some(order => order.addressId === id);

      if (addressInUse) {
        console.log('[Address Delete] Address is in use by orders, cannot delete');
        return res.status(400).json({
          message: 'Cannot delete address because it is being used in existing orders. Please contact support if you need to change this address.'
        });
      }

      const success = await storage.deleteAddress(id);

      if (!success) {
        console.log('[Address Delete] Delete failed');
        return res.status(500).json({ message: 'Failed to delete address' });
      }

      console.log('[Address Delete] Success');
      res.json({ message: 'Address deleted successfully' });
    } catch (error) {
      console.error('[Address Delete] Error:', error);
      res.status(400).json({ message: 'Failed to delete address' });
    }
  });

  app.put('/api/users/me', authenticateToken, async (req: any, res) => {
    try {
      const { name, phone, address, addressCoordinates } = req.body;
      const updates: Partial<any> = {};

      if (name !== undefined) updates.name = name;
      if (phone !== undefined) updates.phone = phone;
      if (address !== undefined) updates.address = address;
      if (addressCoordinates !== undefined) updates.addressCoordinates = addressCoordinates;

      const user = await storage.updateUser(req.user.id, updates);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          phone: user.phone,
          address: user.address,
          addressCoordinates: user.addressCoordinates,
          avatar: user.avatar,
        },
      });
    } catch (error) {
      res.status(400).json({ message: 'Failed to update profile' });
    }
  });

  // Product routes
  app.get('/api/products', async (req, res) => {
    try {
      const products = await storage.getProducts();
      res.json(products);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch products' });
    }
  });

  app.post('/api/products', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const productData = insertProductSchema.parse(req.body);
      const product = await storage.createProduct(productData);
      res.status(201).json(product);
    } catch (error) {
      res.status(400).json({ message: 'Invalid product data' });
    }
  });

  app.put('/api/products/:id', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      const product = await storage.updateProduct(id, updates);

      if (!product) {
        return res.status(404).json({ message: 'Product not found' });
      }

      res.json(product);
    } catch (error) {
      res.status(400).json({ message: 'Failed to update product' });
    }
  });

  app.delete('/api/products/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      console.log('DELETE route called for product:', id);

      const product = await storage.getProduct(id);
      console.log('Product lookup result:', product);

      if (!product) {
        console.log('Product not found');
        return res.status(404).json({ message: 'Product not found' });
      }

      console.log('Calling storage.deleteProduct');
      const success = await storage.deleteProduct(id);
      console.log('Storage delete result:', success);

      if (!success) {
        console.log('Storage delete returned false');
        return res.status(500).json({ message: 'Failed to delete product' });
      }

      console.log('Delete successful');
      res.json({ message: 'Product deleted successfully' });
    } catch (error) {
      console.error('Route error:', error);
      res.status(500).json({ message: 'Failed to delete product' });
    }
  });

  // Cart routes
  app.get('/api/cart', authenticateToken, async (req: any, res) => {
    try {
      const cartItems = await storage.getCartItems(req.user.id);
      res.json(cartItems);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch cart items' });
    }
  });

  app.post('/api/cart', authenticateToken, async (req: any, res) => {
    try {
      const cartItemData = {
        ...req.body,
        userId: req.user.id,
      };
      const cartItem = await storage.addCartItem(cartItemData);
      res.status(201).json(cartItem);
    } catch (error) {
      res.status(400).json({ message: 'Failed to add item to cart' });
    }
  });

  app.put('/api/cart/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { quantity } = req.body;
      const cartItem = await storage.updateCartItem(id, quantity);
      
      if (!cartItem) {
        return res.status(404).json({ message: 'Cart item not found' });
      }
      
      res.json(cartItem);
    } catch (error) {
      res.status(400).json({ message: 'Failed to update cart item' });
    }
  });

  app.delete('/api/cart/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const success = await storage.removeCartItem(id);
      
      if (!success) {
        return res.status(404).json({ message: 'Cart item not found' });
      }
      
      res.json({ message: 'Item removed from cart' });
    } catch (error) {
      res.status(400).json({ message: 'Failed to remove item from cart' });
    }
  });

  app.delete('/api/cart', authenticateToken, async (req: any, res) => {
    try {
      await storage.clearCart(req.user.id);
      res.json({ message: 'Cart cleared' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to clear cart' });
    }
  });

  // Order routes
  app.get('/api/orders', authenticateToken, async (req: any, res) => {
    try {
      let orders;
      if (req.user.role === 'admin') {
        orders = await storage.getOrders();
      } else {
        orders = await storage.getOrdersByCustomer(req.user.id);
      }
      res.json(orders);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch orders' });
    }
  });

  app.get('/api/orders/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const order = await storage.getOrderById(id);

      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }

      // Check if user has permission to view this order
      if (req.user.role !== 'admin' && order.customerId !== req.user.id) {
        return res.status(403).json({ message: 'Access denied' });
      }

      res.json(order);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch order' });
    }
  });

  app.post('/api/orders', authenticateToken, async (req: any, res) => {
    try {
      const orderData = insertOrderSchema.parse({
        ...req.body,
        customerId: req.user.id,
      });

      const order = await storage.createOrderAndUpdateStock(orderData);
      
      // Clear cart after successful order
      await storage.clearCart(req.user.id);
      
      // Create notification for customer
      await storage.createNotification({
        userId: req.user.id,
        title: 'Order Placed',
        message: `Your order ${order.orderNumber} has been placed successfully.`,
        type: 'order_update',
        data: { orderId: order.id },
      });

      // Create notifications for all admin users (prevent duplicates)
      const adminUsers = await storage.getAllUsers();
      const admins = adminUsers.filter(user => user.role === 'admin');
      for (const admin of admins) {
        // Check if notification already exists for this order and admin
        const existingNotifications = await storage.getUserNotifications(admin.id);
        const notificationExists = existingNotifications.some(n => {
          if (n.type !== 'order_update' || !n.data) return false;
          const data = typeof n.data === 'string' ? JSON.parse(n.data) : n.data;
          return data.orderId === order.id;
        });

        if (!notificationExists) {
          await storage.createNotification({
            userId: admin.id,
            title: 'New Order Received',
            message: `Order ${order.orderNumber} has been placed by a customer.`,
            type: 'order_update',
            data: { orderId: order.id },
          });
        }

        // Broadcast real-time notification to connected admin via WebSocket
        const adminWs = clients.get(admin.id);
        if (adminWs && adminWs.readyState === WebSocket.OPEN) {
          adminWs.send(JSON.stringify({
            type: 'new_order',
            order: order,
            message: `New order ${order.orderNumber} received`,
          }));
        }
      }
      
      res.status(201).json(order);
    } catch (error: any) {
      console.error('Order creation error:', error);
      res.status(400).json({ message: error.message || 'Failed to create order' });
    }
  });

  app.put('/api/orders/:id/status', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;
      const order = await storage.updateOrderStatus(id, status);

      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }

      // Create notification for customer (prevent duplicates)
      const customerNotifications = await storage.getUserNotifications(order.customerId);
      const customerNotificationExists = customerNotifications.some(n => {
        if (n.type !== 'order_update' || !n.data) return false;
        const data = typeof n.data === 'string' ? JSON.parse(n.data) : n.data;
        return data.orderId === order.id && n.message.includes(`status has been updated to ${status}`);
      });

      if (!customerNotificationExists) {
        await storage.createNotification({
          userId: order.customerId,
          title: 'Order Update',
          message: `Your order ${order.orderNumber} status has been updated to ${status}.`,
          type: 'order_update',
          data: { orderId: order.id },
        });
      }

      // Broadcast update via WebSocket
      const customerWs = clients.get(order.customerId);
      if (customerWs && customerWs.readyState === WebSocket.OPEN) {
        customerWs.send(JSON.stringify({
          type: 'order_status_update',
          order: order,
        }));
      }

      res.json(order);
    } catch (error) {
      res.status(400).json({ message: 'Failed to update order status' });
    }
  });

  // Submit payment reference
  app.put('/api/orders/:id/payment-reference', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { referenceNumber, proofOfPayment } = req.body;

      // Get the order
      const order = await storage.getOrderById(id);
      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }

      // Check if user owns the order
      if (req.user.role !== 'admin' && order.customerId !== req.user.id) {
        return res.status(403).json({ message: 'Access denied' });
      }

      // Check if order uses bank transfer
      if (order.paymentMethod !== 'bank_transfer') {
        return res.status(400).json({ message: 'Payment reference submission is only for bank transfer payments' });
      }

      // Update order with payment reference
      const updatedOrder = await storage.updateOrder(id, {
        referenceNumber,
        proofOfPayment,
        paymentVerificationStatus: 'pending',
        submittedAt: new Date(),
      });

      if (!updatedOrder) {
        return res.status(500).json({ message: 'Failed to update order' });
      }

      // Create notification for customer (if submitted by admin) or for admin
      if (req.user.role === 'admin') {
        await storage.createNotification({
          userId: order.customerId,
          title: 'Payment Reference Submitted',
          message: `Payment reference has been submitted for your order ${order.orderNumber}.`,
          type: 'order_update',
          data: { orderId: order.id },
        });
      }

      res.json(updatedOrder);
    } catch (error) {
      console.error('Payment reference submission error:', error);
      res.status(500).json({ message: 'Failed to submit payment reference' });
    }
  });

  // Admin payment verification
  app.put('/api/orders/:id/payment-verification', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { action } = req.body; // 'verify' or 'reject'

      if (!['verify', 'reject'].includes(action)) {
        return res.status(400).json({ message: 'Invalid action. Must be "verify" or "reject"' });
      }

      const order = await storage.getOrderById(id);
      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }

      const updates: any = {
        paymentVerificationStatus: action === 'verify' ? 'verified' : 'rejected',
        verifiedAt: new Date(),
        verifiedBy: req.user.id,
      };

      if (action === 'verify') {
        updates.paymentStatus = 'paid';
      }

      const updatedOrder = await storage.updateOrder(id, updates);

      if (!updatedOrder) {
        return res.status(500).json({ message: 'Failed to update order' });
      }

      // Create notification for customer (prevent duplicates)
      const customerNotifications = await storage.getUserNotifications(order.customerId);
      const customerNotificationExists = customerNotifications.some(n => {
        if (n.type !== 'order_update' || !n.data) return false;
        const data = typeof n.data === 'string' ? JSON.parse(n.data) : n.data;
        return data.orderId === order.id && n.message.includes(`payment for order ${order.orderNumber} has been ${action === 'verify' ? 'verified' : 'rejected'}`);
      });

      if (!customerNotificationExists) {
        await storage.createNotification({
          userId: order.customerId,
          title: action === 'verify' ? 'Payment Verified' : 'Payment Rejected',
          message: `Your payment for order ${order.orderNumber} has been ${action === 'verify' ? 'verified' : 'rejected'}.`,
          type: 'order_update',
          data: { orderId: order.id },
        });
      }

      // Broadcast update via WebSocket
      const customerWs = clients.get(order.customerId);
      if (customerWs && customerWs.readyState === WebSocket.OPEN) {
        customerWs.send(JSON.stringify({
          type: 'order_status_update',
          order: order,
        }));
      }

      res.json(updatedOrder);
    } catch (error) {
      console.error('Payment verification error:', error);
      res.status(500).json({ message: 'Failed to process payment verification' });
    }
  });

  // Admin location tracking routes
  app.get('/api/admin/addresses', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const addresses = await storage.getAllAddressesWithUsers();
      console.log('[Admin Addresses] Fetched addresses count:', addresses.length);
      addresses.forEach((addr, index) => {
        console.log(`[Admin Addresses] Address ${index + 1}:`, {
          id: addr.id,
          user: addr.user.name,
          coordinates: addr.coordinates,
          hasCoordinates: !!addr.coordinates
        });
      });
      res.json(addresses);
    } catch (error) {
      console.error('[Admin Addresses] Error fetching addresses:', error);
      res.status(500).json({ message: 'Failed to fetch addresses' });
    }
  });

  app.get('/api/admin/orders/tracking', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const orders = await storage.getOrdersWithLocationData();
      console.log('[Admin Orders Tracking] Fetched orders with location data count:', orders.length);
      orders.forEach((order, index) => {
        console.log(`[Admin Orders Tracking] Order ${index + 1}:`, {
          id: order.id,
          orderNumber: order.orderNumber,
          customer: order.customer.name,
          addressCoordinates: order.address?.coordinates,
          hasCoordinates: !!order.address?.coordinates
        });
      });
      res.json(orders);
    } catch (error) {
      console.error('[Admin Orders Tracking] Error fetching orders:', error);
      res.status(500).json({ message: 'Failed to fetch orders for tracking' });
    }
  });

  // Delivery Drivers routes
  app.get('/api/admin/delivery-drivers', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const drivers = await storage.getDeliveryDrivers();
      res.json(drivers);
    } catch (error) {
      console.error('[Delivery Drivers] Error fetching drivers:', error);
      res.status(500).json({ message: 'Failed to fetch delivery drivers' });
    }
  });

  app.post('/api/admin/delivery-drivers', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const driverData = req.body;
      const driver = await storage.createDeliveryDriver(driverData);
      res.status(201).json(driver);
    } catch (error) {
      console.error('[Delivery Drivers] Error creating driver:', error);
      res.status(400).json({ message: 'Failed to create delivery driver' });
    }
  });

  app.put('/api/admin/delivery-drivers/:id', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      const driver = await storage.updateDeliveryDriver(id, updates);

      if (!driver) {
        return res.status(404).json({ message: 'Delivery driver not found' });
      }

      res.json(driver);
    } catch (error) {
      console.error('[Delivery Drivers] Error updating driver:', error);
      res.status(400).json({ message: 'Failed to update delivery driver' });
    }
  });

  app.delete('/api/admin/delivery-drivers/:id', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const success = await storage.deleteDeliveryDriver(id);

      if (!success) {
        return res.status(404).json({ message: 'Delivery driver not found' });
      }

      res.json({ message: 'Delivery driver deleted successfully' });
    } catch (error) {
      console.error('[Delivery Drivers] Error deleting driver:', error);
      res.status(400).json({ message: 'Failed to delete delivery driver' });
    }
  });

  // Chat routes
  app.get('/api/chat/messages', authenticateToken, async (req: any, res) => {
    try {
      const { orderId } = req.query;
      const messages = await storage.getChatMessages(req.user.id, orderId as string);
      res.json(messages);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch messages' });
    }
  });

  app.post('/api/chat/messages', authenticateToken, async (req: any, res) => {
    try {
      const messageData = {
        ...req.body,
        senderId: req.user.id,
      };

      // If customer is sending message without specific receiver, default to admin
      if (req.user.role === 'customer' && !messageData.receiverId) {
        const adminUser = await storage.getUserByEmail('admin@gasflow.com');
        if (adminUser) {
          messageData.receiverId = adminUser.id;
        } else {
          // If admin user doesn't exist, create a fallback admin user
          try {
            const fallbackAdmin = await storage.createUser({
              email: 'admin@gasflow.com',
              password: 'admin123',
              name: 'Admin User',
              role: 'admin',
              phone: '+63 912 345 6789',
            });
            await storage.updateUserEmailVerification(fallbackAdmin.id, true);
            messageData.receiverId = fallbackAdmin.id;
          } catch (error) {
            console.error('Failed to create fallback admin user:', error);
            return res.status(500).json({ message: 'Unable to send message - admin user not available' });
          }
        }
      }

      const message = await storage.createChatMessage(messageData);

      // Broadcast message via WebSocket to receiver
      if (messageData.receiverId) {
        const receiverWs = clients.get(messageData.receiverId);
        if (receiverWs && receiverWs.readyState === WebSocket.OPEN) {
          receiverWs.send(JSON.stringify({
            type: 'new_message',
            message: message,
          }));
        }
      }

      res.status(201).json(message);
    } catch (error) {
      res.status(400).json({ message: 'Failed to create message' });
    }
  });

  app.post('/api/chat/messages/read', authenticateToken, async (req: any, res) => {
    try {
      await storage.markMessagesAsRead(req.user.id);
      res.json({ message: 'Messages marked as read' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to mark messages as read' });
    }
  });

  app.put('/api/chat/messages/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { message } = req.body;
      
      if (!message || !message.trim()) {
        return res.status(400).json({ message: 'Message content is required' });
      }
      
      const updatedMessage = await storage.updateChatMessage(id, req.user.id, message.trim());
      
      if (!updatedMessage) {
        return res.status(404).json({ message: 'Message not found or not authorized to edit' });
      }
      
      res.json(updatedMessage);
    } catch (error) {
      res.status(500).json({ message: 'Failed to update message' });
    }
  });

  app.delete('/api/chat/messages/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const success = await storage.deleteChatMessage(id, req.user.id);
      
      if (!success) {
        return res.status(404).json({ message: 'Message not found or not authorized to delete' });
      }
      
      res.json({ message: 'Message deleted successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to delete message' });
    }
  });

  app.delete('/api/chat/messages/:id/unsend', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const success = await storage.unsendChatMessage(id, req.user.id);
      
      if (!success) {
        return res.status(404).json({ message: 'Message not found or not authorized to unsend' });
      }
      
      res.json({ message: 'Message unsent successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to unsend message' });
    }
  });

  // Admin chat routes
  app.get('/api/chat/customers', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const customers = await storage.getChatCustomers();
      res.json(customers);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch chat customers' });
    }
  });

  app.get('/api/chat/conversation/:customerId', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { customerId } = req.params;
      const messages = await storage.getConversationMessages(customerId, req.user.id);
      res.json(messages);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch conversation messages' });
    }
  });

  // Notification routes
  app.get('/api/notifications', authenticateToken, async (req: any, res) => {
    try {
      const notifications = await storage.getUserNotifications(req.user.id);
      res.json(notifications);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch notifications' });
    }
  });

  app.put('/api/notifications/:id/read', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const success = await storage.markNotificationAsRead(id, req.user.id);

      if (!success) {
        return res.status(404).json({ message: 'Notification not found' });
      }

      res.json({ message: 'Notification marked as read' });
    } catch (error) {
      res.status(400).json({ message: 'Failed to mark notification as read' });
    }
  });

  app.delete('/api/notifications/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const success = await storage.deleteNotification(id, req.user.id);

      if (!success) {
        return res.status(404).json({ message: 'Notification not found or not authorized to delete' });
      }

      res.json({ message: 'Notification deleted successfully' });
    } catch (error) {
      res.status(400).json({ message: 'Failed to delete notification' });
    }
  });

  // Get unread order notifications count
  app.get('/api/notifications/unread-order-count', authenticateToken, async (req: any, res) => {
    try {
      const count = await storage.getUnreadOrderNotificationsCount(req.user.id);
      res.json({ count });
    } catch (error) {
      console.error('Error getting unread order notifications count:', error);
      res.status(500).json({ message: 'Failed to get unread order notifications count' });
    }
  });

  // Mark all notifications as read for current user
  app.put('/api/notifications/mark-all-read', authenticateToken, async (req: any, res) => {
    try {
      const count = await storage.markAllNotificationsAsRead(req.user.id);

      res.json({
        message: 'All notifications marked as read',
        count
      });
    } catch (error) {
      console.error('Error marking all notifications as read:', error);
      res.status(500).json({ message: 'Failed to mark all notifications as read' });
    }
  });

  // Mark only general notifications as read (excluding order notifications)
  app.put('/api/notifications/mark-general-read', authenticateToken, async (req: any, res) => {
    try {
      const count = await storage.markGeneralNotificationsAsRead(req.user.id);

      res.json({
        message: 'General notifications marked as read',
        count
      });
    } catch (error) {
      console.error('Error marking general notifications as read:', error);
      res.status(500).json({ message: 'Failed to mark general notifications as read' });
    }
  });

  // Mark all order notifications as read for current user
  app.put('/api/notifications/mark-order-read', authenticateToken, async (req: any, res) => {
    try {
      // Get all unread order notifications for the current user
      const notifications = await storage.getUserNotifications(req.user.id);
      const orderNotifications = notifications.filter(n => !n.isRead && n.type === 'order_update');

      // Mark each one as read
      for (const notification of orderNotifications) {
        await storage.markNotificationAsRead(notification.id, req.user.id);
      }

      res.json({
        message: 'Order notifications marked as read',
        count: orderNotifications.length
      });
    } catch (error) {
      console.error('Error marking order notifications as read:', error);
      res.status(500).json({ message: 'Failed to mark order notifications as read' });
    }
  });

  // Receipt routes
  app.get('/api/orders/:id/receipt', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const orderDetails = await storage.getOrderDetailsForReceipt(id, req.user.id);
      
      if (!orderDetails) {
        return res.status(404).json({ message: 'Order not found or access denied' });
      }
      
      res.json(orderDetails);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch order details for receipt' });
    }
  });

  // Analytics routes (admin only)
  app.get('/api/analytics/dashboard', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch dashboard stats' });
    }
  });

  // Delivery Schedules routes
  app.get('/api/schedules', authenticateToken, async (req: any, res: any) => {
    try {
      const schedules = await storage.getDeliverySchedules(req.user.id);
      res.json(schedules);
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  });

  app.get('/api/admin/schedules', authenticateToken, requireAdmin, async (req: any, res: any) => {
    try {
      const schedules = await storage.getAllDeliverySchedules();
      res.json(schedules);
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  });

  app.post('/api/schedules', authenticateToken, async (req: any, res: any) => {
    try {
      const scheduleData = {
        ...req.body,
        userId: req.user.id
      };

      // Validate required fields
      if (!scheduleData.name || !scheduleData.productId || !scheduleData.addressId) {
        return res.status(400).json({ message: "Missing required fields: name, productId, addressId" });
      }

      // Validate frequency
      if (!['weekly', 'biweekly', 'monthly'].includes(scheduleData.frequency)) {
        return res.status(400).json({ message: "Invalid frequency. Must be 'weekly', 'biweekly', or 'monthly'" });
      }

      // Validate type
      if (!['new', 'swap'].includes(scheduleData.type)) {
        return res.status(400).json({ message: "Invalid type. Must be 'new' or 'swap'" });
      }

      // Validate quantity
      if (!scheduleData.quantity || scheduleData.quantity < 1) {
        return res.status(400).json({ message: "Quantity must be at least 1" });
      }

      // Calculate next delivery date
      const calculateNextDelivery = (
        frequency: "weekly" | "biweekly" | "monthly",
        dayOfWeek?: number,
        dayOfMonth?: number
      ): string => {
        const now = new Date();
        let nextDelivery = new Date();

        if (frequency === "monthly" && dayOfMonth) {
          nextDelivery.setDate(dayOfMonth);
          if (nextDelivery <= now) {
            nextDelivery.setMonth(nextDelivery.getMonth() + 1);
          }
        } else if ((frequency === "weekly" || frequency === "biweekly") && dayOfWeek !== undefined) {
          const days = (dayOfWeek - now.getDay() + 7) % 7;
          nextDelivery.setDate(now.getDate() + days);
          if (nextDelivery <= now) {
            nextDelivery.setDate(nextDelivery.getDate() + (frequency === "weekly" ? 7 : 14));
          }
        }

        return nextDelivery.toISOString();
      };

      // Calculate next delivery date
      const nextDeliveryDate = calculateNextDelivery(
        scheduleData.frequency,
        scheduleData.dayOfWeek,
        scheduleData.dayOfMonth
      );

      const schedule = await storage.createDeliverySchedule({
        ...scheduleData,
        nextDelivery: new Date(nextDeliveryDate),
      });
      res.status(201).json(schedule);
    } catch (error: any) {
      console.error('Create schedule error:', error);
      res.status(500).json({ message: error.message || "Failed to create delivery schedule" });
    }
  });

  app.put('/api/schedules/:id', authenticateToken, async (req: any, res: any) => {
    try {
      const schedule = await storage.updateDeliverySchedule(req.params.id, req.body);
      if (!schedule) {
        return res.status(404).json({ message: 'Schedule not found' });
      }
      res.json(schedule);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  });

  app.delete('/api/schedules/:id', authenticateToken, async (req: any, res: any) => {
    try {
      const success = await storage.deleteDeliverySchedule(req.params.id);
      if (!success) {
        return res.status(404).json({ message: 'Schedule not found' });
      }
      res.status(204).send();
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  });

  // POS System routes
  app.post('/api/pos/sale', posLimiter, authenticateToken, requireAdmin, async (req: any, res: any) => {
    try {
      const { customerId, items, totalAmount, paymentMethod, amountPaid, change } = req.body;
      
      let addressId = "pos-default";
      if (customerId) {
        const addresses = await storage.getUserAddresses(customerId);
        if (addresses && addresses.length > 0) {
          addressId = addresses[0].id;
        }
      }

      const saleData = {
        customerId,
        items,
        totalAmount,
        paymentMethod,
        amountPaid,
        change,
        addressId
      }

      const createdOrders = await storage.createPosSale(saleData);

      res.status(201).json({
        success: true,
        orderId: createdOrders[0].id,
        receiptNumber: createdOrders[0].orderNumber
      });
    } catch (error: any) {
      console.error('POS sale error:', error);
      res.status(500).json({ message: error.message || 'Failed to process sale' });
    }
  });

  app.get('/api/users', authenticateToken, requireAdmin, async (req: any, res: any) => {
    try {
      const role = req.query.role;
      const users = await storage.getAllUsers();
      const filteredUsers = role ? users.filter((user: any) => user.role === role) : users;
      res.json(filteredUsers);
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  });

  // Payment QR Codes routes
  app.get('/api/payment-qr-codes', async (req: any, res: any) => {
    try {
      const qrCodes = await storage.getPaymentQrCodes();
      res.json(qrCodes);
    } catch (error: any) {
      res.status(500).json({ message: 'Failed to fetch payment QR codes' });
    }
  });

  app.post('/api/admin/payment-qr-codes', authenticateToken, requireAdmin, async (req: any, res: any) => {
    try {
      const qrCodeData = insertPaymentQrCodeSchema.parse(req.body);
      const qrCode = await storage.createPaymentQrCode(qrCodeData);
      res.status(201).json(qrCode);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  });

  app.put('/api/admin/payment-qr-codes/:id', authenticateToken, requireAdmin, async (req: any, res: any) => {
    try {
      const { id } = req.params;
      const qrCodeData = insertPaymentQrCodeSchema.partial().parse(req.body);
      const qrCode = await storage.updatePaymentQrCode(id, qrCodeData);
      if (!qrCode) {
        return res.status(404).json({ message: 'QR code not found' });
      }
      res.json(qrCode);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  });

  app.delete('/api/admin/payment-qr-codes/:id', authenticateToken, requireAdmin, async (req: any, res: any) => {
    try {
      const { id } = req.params;
      const success = await storage.deletePaymentQrCode(id);
      if (!success) {
        return res.status(404).json({ message: 'QR code not found' });
      }
      res.json({ message: 'QR code deleted successfully' });
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  });

  // Image upload endpoint
  const upload = multer({
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed'));
      }
    },
  });

  // Physical Store Sales routes
  app.get('/api/physical-sales', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const physicalSales = await storage.getPhysicalSales();
      res.json(physicalSales);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch physical sales' });
    }
  });

  app.post('/api/physical-sales', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { productId, type, quantity, customerName, customerPhone, notes } = req.body;

      // Validate required fields
      if (!productId || !type || !quantity) {
        return res.status(400).json({ message: 'Product ID, type, and quantity are required' });
      }

      if (!['new', 'swap'].includes(type)) {
        return res.status(400).json({ message: 'Type must be either "new" or "swap"' });
      }

      if (quantity < 1) {
        return res.status(400).json({ message: 'Quantity must be at least 1' });
      }

      // Get product details to calculate price.
      // The stock check will be done in the transaction.
      const product = await storage.getProduct(productId);
      if (!product) {
        return res.status(404).json({ message: 'Product not found' });
      }

      // Calculate pricing
      const unitPrice = type === 'new' ? parseFloat(product.newPrice) : parseFloat(product.swapPrice);
      const totalAmount = unitPrice * quantity;

      // Create physical sale record
      const physicalSale = await storage.createPhysicalSaleAndUpdateStock({
        productId,
        type,
        quantity,
        unitPrice: unitPrice.toString(),
        totalAmount: totalAmount.toString(),
        customerName: customerName || null,
        customerPhone: customerPhone || null,
        notes: notes || null,
      });

      res.status(201).json(physicalSale);
    } catch (error: any) {
      console.error('Physical sale creation error:', error);
      res.status(500).json({ message: error.message || 'Failed to create physical sale' });
    }
  });

  app.post('/api/upload/image', authenticateToken, upload.single('file'), async (req: any, res: any) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
      }

      // Upload to Supabase Storage
      const { createClient } = await import('@supabase/supabase-js');

      const supabaseUrl = process.env.SUPABASE_URL;
      const supabaseKey = process.env.SUPABASE_ANON_KEY;

      console.log('Supabase URL:', supabaseUrl);
      console.log('Supabase Key exists:', !!supabaseKey);

      if (!supabaseUrl || !supabaseKey) {
        throw new Error('Supabase configuration missing');
      }

      const supabase = createClient(supabaseUrl, supabaseKey);
      console.log('Supabase client created successfully');

      // Generate unique filename
      const fileExt = req.file.originalname.split('.').pop();
      const fileName = `${Date.now()}-${Math.random().toString(36).substring(2)}.${fileExt}`;

      console.log('File details:', {
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
        generatedFileName: fileName
      });

      // Upload file to Supabase bucket
      console.log('Attempting to upload to bucket: images');
      const { data, error } = await supabase.storage
        .from('images')
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      console.log('Upload result:', { data, error });

      if (error) {
        console.error('Supabase upload error:', error);
        console.error('Error details:', JSON.stringify(error, null, 2));
        throw new Error(`Failed to upload image to storage: ${error.message}`);
      }

      // Get public URL
      const { data: urlData } = supabase.storage
        .from('images')
        .getPublicUrl(fileName);

      if (!urlData.publicUrl) {
        throw new Error('Failed to get public URL');
      }

      res.json({
        message: 'Image uploaded successfully',
        imageUrl: urlData.publicUrl,
        filename: fileName,
        size: req.file.size
      });
    } catch (error: any) {
      console.error('Image upload error:', error);
      res.status(500).json({ message: error.message || 'Failed to upload image' });
    }
  });

  // Payment QR Code routes (admin only)
  app.get('/api/admin/payment-qr-codes', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const qrCodes = await storage.getPaymentQrCodes();
      res.json(qrCodes);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch payment QR codes' });
    }
  });

  app.post('/api/admin/payment-qr-codes', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const qrCodeData = insertPaymentQrCodeSchema.parse(req.body);
      const qrCode = await storage.createPaymentQrCode(qrCodeData);
      res.status(201).json(qrCode);
    } catch (error) {
      res.status(400).json({ message: 'Invalid QR code data' });
    }
  });

  app.put('/api/admin/payment-qr-codes/:id', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      const qrCode = await storage.updatePaymentQrCode(id, updates);

      if (!qrCode) {
        return res.status(404).json({ message: 'Payment QR code not found' });
      }

      res.json(qrCode);
    } catch (error) {
      res.status(400).json({ message: 'Failed to update payment QR code' });
    }
  });

  app.delete('/api/admin/payment-qr-codes/:id', authenticateToken, requireAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const success = await storage.deletePaymentQrCode(id);

      if (!success) {
        return res.status(404).json({ message: 'Payment QR code not found' });
      }

      res.json({ message: 'Payment QR code deleted successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to delete payment QR code' });
    }
  });

  return httpServer;
}
