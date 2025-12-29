import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import { eq, desc, and, or, count, sum, sql as drizzleSql, gt, ne, not, inArray } from "drizzle-orm";
import {
  type User,
  type InsertUser,
  type Address,
  type InsertAddress,
  type Product,
  type InsertProduct,
  type Order,
  type InsertOrder,
  type CartItem,
  type InsertCartItem,
  type ChatMessage,
  type InsertChatMessage,
  type Notification,
  type InsertNotification,
  type DeliverySchedule,
  type InsertDeliverySchedule,
  type DeliveryDriver,
  type InsertDeliveryDriver,
  type PhysicalSale,
  type InsertPhysicalSale,
  type PaymentQrCode,
  type InsertPaymentQrCode,
  users,
  addresses,
  products,
  orders,
  cartItems,
  chatMessages,
  notifications,
  deliverySchedules,
  deliveryDrivers,
  physicalSales,
  paymentQrCodes
} from "./shared/schema";
import { randomUUID } from "crypto";
import bcrypt from "bcrypt";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set");
}

const sql = postgres(process.env.DATABASE_URL!);
const db = drizzle(sql);

export interface IStorage {
  // Users
  getUserById(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getAllUsers(): Promise<User[]>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<User | undefined>;
  
  // Auth
  validateUser(email: string, password: string): Promise<User | null>;
  
  // Addresses
  getUserAddresses(userId: string): Promise<Address[]>;
  getAllAddressesWithUsers(): Promise<any[]>;
  createAddress(address: InsertAddress): Promise<Address>;
  updateAddress(id: string, updates: Partial<InsertAddress>): Promise<Address | undefined>;
  deleteAddress(id: string): Promise<boolean>;
  
  // Products
  getProducts(): Promise<Product[]>;
  getProduct(id: string): Promise<Product | undefined>;
  getProductById(id: string): Promise<Product | undefined>;
  createProduct(product: InsertProduct): Promise<Product>;
  updateProduct(id: string, updates: Partial<InsertProduct>): Promise<Product | undefined>;
  updateProductStock(id: string, stock: number): Promise<Product | undefined>;
  deleteProduct(id: string): Promise<boolean>;
  
  // Orders
  getOrders(): Promise<Order[]>;
  getOrdersByCustomer(customerId: string): Promise<Order[]>;
  getOrderById(id: string): Promise<Order | undefined>;
  getOrdersWithLocationData(): Promise<any[]>;
  createOrderAndUpdateStock(orderData: InsertOrder): Promise<Order>;
  updateOrder(id: string, updates: Partial<Order>): Promise<Order | undefined>;
  updateOrderStatus(id: string, status: string): Promise<Order | undefined>;
  
  // Cart
  getCartItems(userId: string): Promise<CartItem[]>;
  addCartItem(item: InsertCartItem): Promise<CartItem>;
  updateCartItem(id: string, quantity: number): Promise<CartItem | undefined>;
  removeCartItem(id: string): Promise<boolean>;
  clearCart(userId: string): Promise<boolean>;
  
  // Chat
  getChatMessages(userId: string, orderId?: string): Promise<ChatMessage[]>;
  createChatMessage(message: InsertChatMessage): Promise<ChatMessage>;
  updateChatMessage(messageId: string, userId: string, newMessage: string): Promise<ChatMessage | null>;
  deleteChatMessage(messageId: string, userId: string): Promise<boolean>;
  unsendChatMessage(messageId: string, userId: string): Promise<boolean>;
  markMessagesAsRead(userId: string): Promise<boolean>;
  getChatCustomers(): Promise<any[]>;
  getConversationMessages(customerId: string, adminId: string): Promise<ChatMessage[]>;
  
  // Notifications
  getUserNotifications(userId: string): Promise<Notification[]>;
  getUnreadOrderNotificationsCount(userId: string): Promise<number>;
  markAllNotificationsAsRead(userId: string): Promise<number>;
  markGeneralNotificationsAsRead(userId: string): Promise<number>;
  createNotification(notification: InsertNotification): Promise<Notification>;
  markNotificationAsRead(id: string, userId: string): Promise<boolean>;
  deleteNotification(id: string, userId: string): Promise<boolean>;
  
  // Delivery Schedules
  getDeliverySchedules(userId: string): Promise<any[]>;
  getAllDeliverySchedules(): Promise<DeliverySchedule[]>;
  getDeliveryScheduleById(id: string): Promise<DeliverySchedule | undefined>;
  createDeliverySchedule(schedule: InsertDeliverySchedule): Promise<DeliverySchedule>;
  updateDeliverySchedule(id: string, updates: Partial<InsertDeliverySchedule>): Promise<DeliverySchedule | undefined>;
  deleteDeliverySchedule(id: string): Promise<boolean>;
  
  // Analytics
  getDashboardStats(): Promise<{
    totalSales: number;
    totalOrders: number;
    pendingOrders: number;
    activeCustomers: number;
  }>;
  
  // Receipt
  getOrderDetailsForReceipt(orderId: string, userId: string): Promise<any>;
  
  // Email verification
  updateUserEmailVerification(id: string, verified: boolean): Promise<User | undefined>;
  setEmailVerificationToken(id: string, token: string, expires: Date): Promise<User | undefined>;
  getUserByVerificationToken(token: string): Promise<User | undefined>;
  clearEmailVerificationToken(id: string): Promise<User | undefined>;

  // Password reset
  setPasswordResetToken(id: string, token: string, expires: Date): Promise<User | undefined>;
  getUserByPasswordResetToken(token: string): Promise<User | undefined>;
  clearPasswordResetToken(id: string): Promise<User | undefined>;

  // Delivery Drivers
  getDeliveryDrivers(): Promise<any[]>;
  createDeliveryDriver(driver: any): Promise<any>;
  updateDeliveryDriver(id: string, updates: any): Promise<any>;
  deleteDeliveryDriver(id: string): Promise<boolean>;

  // POS
  createPosSale(saleData: any): Promise<Order[]>;

  // Physical Sales
  getPhysicalSales(): Promise<any[]>;
  createPhysicalSaleAndUpdateStock(sale: InsertPhysicalSale): Promise<PhysicalSale>;

  // Payment QR Codes
  getPaymentQrCodes(): Promise<PaymentQrCode[]>;
  createPaymentQrCode(qrCode: InsertPaymentQrCode): Promise<PaymentQrCode>;
  updatePaymentQrCode(id: string, updates: Partial<InsertPaymentQrCode>): Promise<PaymentQrCode | undefined>;
  deletePaymentQrCode(id: string): Promise<boolean>;

  // Seed data
  seedData(): Promise<void>;
}

export class DrizzleStorage implements IStorage {
  async getUserById(id: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return result[0];
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.email, email)).limit(1);
    return result[0];
  }

  async getAllUsers(): Promise<User[]> {
    return await db.select().from(users).orderBy(desc(users.createdAt));
  }

  async createUser(user: InsertUser): Promise<User> {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    const result = await db.insert(users).values({
      ...user,
      password: hashedPassword,
    }).returning();
    return result[0];
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User | undefined> {
    const updatableData: { [key: string]: any } = {};
    const allowedFields: (keyof User)[] = ['name', 'email', 'role', 'phone', 'address', 'addressCoordinates', 'avatar', 'emailVerified', 'emailVerificationToken', 'emailVerificationExpires', 'passwordResetToken', 'passwordResetExpires'];

    for (const field of allowedFields) {
        if (updates[field] !== undefined) {
            updatableData[field] = updates[field];
        }
    }

    if (updates.password) {
      updatableData.password = await bcrypt.hash(updates.password, 10);
    }

    if (Object.keys(updatableData).length === 0) {
        // Nothing to update
        return this.getUserById(id);
    }

    const result = await db.update(users).set({
      ...updatableData,
      updatedAt: new Date(),
    }).where(eq(users.id, id)).returning();
    return result[0];
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.getUserByEmail(email);
    if (!user) return null;
    
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? user : null;
  }

  async getUserAddresses(userId: string): Promise<Address[]> {
    return await db.select().from(addresses).where(eq(addresses.userId, userId));
  }

  async createAddress(address: InsertAddress): Promise<Address> {
    const result = await db.insert(addresses).values(address).returning();
    return result[0];
  }

  async updateAddress(id: string, updates: Partial<InsertAddress>): Promise<Address | undefined> {
    const result = await db.update(addresses).set(updates).where(eq(addresses.id, id)).returning();
    return result[0];
  }

  async deleteAddress(id: string): Promise<boolean> {
    const result = await db.delete(addresses).where(eq(addresses.id, id)).returning();
    return result.length > 0;
  }

  async getAllAddressesWithUsers(): Promise<any[]> {
    const result = await db.select({
      id: addresses.id,
      label: addresses.label,
      street: addresses.street,
      city: addresses.city,
      province: addresses.province,
      zipCode: addresses.zipCode,
      coordinates: addresses.coordinates,
      isDefault: addresses.isDefault,
      user: {
        id: users.id,
        name: users.name,
        email: users.email,
        phone: users.phone,
      }
    })
    .from(addresses)
    .innerJoin(users, eq(addresses.userId, users.id));
    
    // Filter out null coordinates in memory for now
    return result.filter(addr => addr.coordinates != null);
  }

  async getProducts(): Promise<Product[]> {
    return await db.select().from(products).where(eq(products.isActive, true));
  }

  async getProduct(id: string): Promise<Product | undefined> {
    const result = await db.select().from(products).where(eq(products.id, id)).limit(1);
    return result[0];
  }

  async getProductById(id: string): Promise<Product | undefined> {
    const result = await db.select().from(products).where(eq(products.id, id)).limit(1);
    return result[0];
  }

  async createProduct(product: InsertProduct): Promise<Product> {
    const result = await db.insert(products).values(product).returning();
    return result[0];
  }

  async updateProduct(id: string, updates: Partial<InsertProduct>): Promise<Product | undefined> {
    const result = await db.update(products).set({
      ...updates,
      updatedAt: new Date(),
    }).where(eq(products.id, id)).returning();
    return result[0];
  }

  async updateProductStock(id: string, stock: number): Promise<Product | undefined> {
    const result = await db.update(products).set({
      stock,
      updatedAt: new Date(),
    }).where(eq(products.id, id)).returning();
    return result[0];
  }

  async deleteProduct(id: string): Promise<boolean> {
    try {
      console.log('Attempting to delete product:', id);
      // First check if product exists
      const existingProduct = await this.getProduct(id);
      console.log('Existing product:', existingProduct);

      if (!existingProduct) {
        console.log('Product not found');
        return false;
      }

      await db.update(products).set({
        isActive: false,
      }).where(eq(products.id, id));
      console.log('Update completed');
      return true;
    } catch (error) {
      console.error('Delete product error:', error);
      return false;
    }
  }

  async getOrders(): Promise<Order[]> {
    return await db.select({
      id: orders.id,
      orderNumber: orders.orderNumber,
      customerId: orders.customerId,
      productId: orders.productId,
      addressId: orders.addressId,
      quantity: orders.quantity,
      type: orders.type,
      unitPrice: orders.unitPrice,
      costPrice: orders.costPrice,
      totalAmount: orders.totalAmount,
      status: orders.status,
      paymentMethod: orders.paymentMethod,
      paymentStatus: orders.paymentStatus,
      paymentVerificationStatus: orders.paymentVerificationStatus,
      referenceNumber: orders.referenceNumber,
      proofOfPayment: orders.proofOfPayment,
      submittedAt: orders.submittedAt,
      verifiedAt: orders.verifiedAt,
      verifiedBy: orders.verifiedBy,
      notes: orders.notes,
      scheduledDate: orders.scheduledDate,
      deliveredAt: orders.deliveredAt,
      createdAt: orders.createdAt,
      updatedAt: orders.updatedAt,
      product: {
        id: products.id,
        name: products.name,
        weight: products.weight,
        newPrice: products.newPrice,
        swapPrice: products.swapPrice,
      }
    })
    .from(orders)
    .leftJoin(products, eq(orders.productId, products.id))
    .orderBy(desc(orders.createdAt));
  }

  async getOrdersByCustomer(customerId: string): Promise<Order[]> {
    return await db.select({
      id: orders.id,
      orderNumber: orders.orderNumber,
      customerId: orders.customerId,
      productId: orders.productId,
      addressId: orders.addressId,
      quantity: orders.quantity,
      type: orders.type,
      unitPrice: orders.unitPrice,
      costPrice: orders.costPrice,
      totalAmount: orders.totalAmount,
      status: orders.status,
      paymentMethod: orders.paymentMethod,
      paymentStatus: orders.paymentStatus,
      paymentVerificationStatus: orders.paymentVerificationStatus,
      referenceNumber: orders.referenceNumber,
      proofOfPayment: orders.proofOfPayment,
      submittedAt: orders.submittedAt,
      verifiedAt: orders.verifiedAt,
      verifiedBy: orders.verifiedBy,
      notes: orders.notes,
      scheduledDate: orders.scheduledDate,
      deliveredAt: orders.deliveredAt,
      createdAt: orders.createdAt,
      updatedAt: orders.updatedAt,
      product: {
        id: products.id,
        name: products.name,
        weight: products.weight,
        newPrice: products.newPrice,
        swapPrice: products.swapPrice,
      }
    })
    .from(orders)
    .leftJoin(products, eq(orders.productId, products.id))
    .where(eq(orders.customerId, customerId))
    .orderBy(desc(orders.createdAt));
  }

  async getOrderById(id: string): Promise<Order | undefined> {
    const result = await db.select({
      id: orders.id,
      orderNumber: orders.orderNumber,
      customerId: orders.customerId,
      productId: orders.productId,
      addressId: orders.addressId,
      quantity: orders.quantity,
      type: orders.type,
      unitPrice: orders.unitPrice,
      costPrice: orders.costPrice,
      totalAmount: orders.totalAmount,
      status: orders.status,
      paymentMethod: orders.paymentMethod,
      paymentStatus: orders.paymentStatus,
      paymentVerificationStatus: orders.paymentVerificationStatus,
      referenceNumber: orders.referenceNumber,
      proofOfPayment: orders.proofOfPayment,
      submittedAt: orders.submittedAt,
      verifiedAt: orders.verifiedAt,
      verifiedBy: orders.verifiedBy,
      notes: orders.notes,
      scheduledDate: orders.scheduledDate,
      deliveredAt: orders.deliveredAt,
      createdAt: orders.createdAt,
      updatedAt: orders.updatedAt,
      product: {
        id: products.id,
        name: products.name,
        weight: products.weight,
        newPrice: products.newPrice,
        swapPrice: products.swapPrice,
      }
    })
    .from(orders)
    .leftJoin(products, eq(orders.productId, products.id))
    .where(eq(orders.id, id))
    .limit(1);
    return result[0];
  }



  async createOrderAndUpdateStock(orderData: InsertOrder): Promise<Order> {
    return await db.transaction(async (tx) => {
      const productResult = await tx.select().from(products).where(eq(products.id, orderData.productId)).for('update').limit(1);

      if (productResult.length === 0) {
        throw new Error("Product not found");
      }
      const product = productResult[0];

      // Only check and reduce stock for 'new' type orders, not 'swap'
      if (orderData.type === 'new') {
        if (product.stock < (orderData.quantity || 1)) {
          throw new Error(`Insufficient stock. Only ${product.stock} units available.`);
        }

        const newStock = product.stock - (orderData.quantity || 1);
        await tx.update(products).set({ stock: newStock }).where(eq(products.id, orderData.productId));
      }

      // Generate unique order number with timestamp and random suffix
      const timestamp = Date.now();
      const randomSuffix = Math.random().toString(36).substring(2, 5).toUpperCase();
      const orderNumber = `GF-${product.name}
      ${timestamp}-${randomSuffix}`;
      
      const newOrder = await tx.insert(orders).values({
        ...orderData,
        costPrice: product.wholesalePrice,
        orderNumber,
      }).returning();
      
      return newOrder[0];
    });
  }

  async updateOrder(id: string, updates: Partial<Order>): Promise<Order | undefined> {
    const result = await db.update(orders).set({
      ...updates,
      updatedAt: new Date(),
    }).where(eq(orders.id, id)).returning();
    return result[0];
  }

  async updateOrderStatus(id: string, status: string): Promise<Order | undefined> {
    const updates: any = { status, updatedAt: new Date() };
    if (status === 'delivered') {
      updates.deliveredAt = new Date();
    }
    const result = await db.update(orders).set(updates).where(eq(orders.id, id)).returning();
    return result[0];
  }

  async getOrdersWithLocationData(): Promise<any[]> {
    const result = await db.select({
      id: orders.id,
      orderNumber: orders.orderNumber,
      status: orders.status,
      createdAt: orders.createdAt,
      quantity: orders.quantity,
      type: orders.type,
      unitPrice: orders.unitPrice,
      totalAmount: orders.totalAmount,
      paymentMethod: orders.paymentMethod,
      paymentStatus: orders.paymentStatus,
      notes: orders.notes,
      customer: {
        id: users.id,
        name: users.name,
        email: users.email,
        phone: users.phone,
      },
      address: {
        id: addresses.id,
        street: addresses.street,
        city: addresses.city,
        province: addresses.province,
        zipCode: addresses.zipCode,
        coordinates: addresses.coordinates,
      }
    })
    .from(orders)
    .innerJoin(users, eq(orders.customerId, users.id))
    .leftJoin(addresses, eq(orders.addressId, addresses.id))
    .orderBy(desc(orders.createdAt));

    // Filter in memory for active orders with coordinates
    return result.filter(order =>
      order.address?.coordinates != null &&
      ['pending', 'processing', 'out_for_delivery'].includes(order.status)
    );
  }

  async getCartItems(userId: string): Promise<CartItem[]> {
    return await db.select({
      id: cartItems.id,
      userId: cartItems.userId,
      productId: cartItems.productId,
      quantity: cartItems.quantity,
      type: cartItems.type,
      createdAt: cartItems.createdAt,
      product: {
        id: products.id,
        name: products.name,
        weight: products.weight,
        newPrice: products.newPrice,
        swapPrice: products.swapPrice,
      }
    })
    .from(cartItems)
    .leftJoin(products, eq(cartItems.productId, products.id))
    .where(eq(cartItems.userId, userId));
  }

  async addCartItem(item: InsertCartItem): Promise<CartItem> {
    // Check if item already exists
    const existing = await db.select().from(cartItems)
      .where(and(
        eq(cartItems.userId, item.userId),
        eq(cartItems.productId, item.productId),
        eq(cartItems.type, item.type)
      )).limit(1);

    if (existing.length > 0) {
      // Update quantity
      const result = await db.update(cartItems)
        .set({ quantity: (existing[0].quantity || 0) + (item.quantity || 1) })
        .where(eq(cartItems.id, existing[0].id))
        .returning();
      return {
        ...result[0],
        product: await this.getProduct(item.productId) || undefined
      } as CartItem;
    } else {
      // Insert new item
      const result = await db.insert(cartItems).values(item).returning();
      return {
        ...result[0],
        product: await this.getProduct(item.productId) || undefined
      } as CartItem;
    }
  }

  async updateCartItem(id: string, quantity: number): Promise<CartItem | undefined> {
    const result = await db.update(cartItems)
      .set({ quantity })
      .where(eq(cartItems.id, id))
      .returning();

    if (result[0]) {
      const product = await this.getProduct(result[0].productId);
      return {
        ...result[0],
        product: product || undefined
      } as CartItem;
    }
    return undefined;
  }

  async removeCartItem(id: string): Promise<boolean> {
    const result = await db.delete(cartItems).where(eq(cartItems.id, id)).returning();
    return result.length > 0;
  }

  async clearCart(userId: string): Promise<boolean> {
    const result = await db.delete(cartItems).where(eq(cartItems.userId, userId)).returning();
    return result.length > 0;
  }

  async getChatMessages(userId: string, orderId?: string): Promise<ChatMessage[]> {
    if (orderId) {
      return await db.select().from(chatMessages)
        .where(and(
          eq(chatMessages.orderId, orderId),
          eq(chatMessages.isDeleted, false)
        ))
        .orderBy(chatMessages.createdAt);
    } else {
      return await db.select().from(chatMessages)
        .where(and(
          or(
            eq(chatMessages.senderId, userId),
            eq(chatMessages.receiverId, userId)
          ),
          eq(chatMessages.isDeleted, false)
        ))
        .orderBy(chatMessages.createdAt);
    }
  }

  async createChatMessage(message: InsertChatMessage): Promise<ChatMessage> {
    const result = await db.insert(chatMessages).values(message).returning();
    return result[0];
  }

  async updateChatMessage(messageId: string, userId: string, newMessage: string): Promise<ChatMessage | null> {
    const result = await db.update(chatMessages)
      .set({ 
        message: newMessage,
        isEdited: true,
        editedAt: new Date()
      })
      .where(and(
        eq(chatMessages.id, messageId),
        eq(chatMessages.senderId, userId), // Only sender can edit their own messages
        eq(chatMessages.isDeleted, false)
      ))
      .returning();
    
    return result.length > 0 ? result[0] : null;
  }

  async deleteChatMessage(messageId: string, userId: string): Promise<boolean> {
    const result = await db.update(chatMessages)
      .set({ 
        isDeleted: true,
        deletedAt: new Date()
      })
      .where(and(
        eq(chatMessages.id, messageId),
        eq(chatMessages.senderId, userId), // Only sender can delete their own messages
        eq(chatMessages.isDeleted, false)
      ))
      .returning();
    
    return result.length > 0;
  }

  async unsendChatMessage(messageId: string, userId: string): Promise<boolean> {
    // Completely remove the message from database (hard delete)
    const result = await db.delete(chatMessages)
      .where(and(
        eq(chatMessages.id, messageId),
        eq(chatMessages.senderId, userId) // Only sender can unsend their own messages
      ))
      .returning();
    
    return result.length > 0;
  }

  async markMessagesAsRead(userId: string): Promise<boolean> {
    const result = await db.update(chatMessages)
      .set({ isRead: true })
      .where(eq(chatMessages.receiverId, userId))
      .returning();
    return result.length > 0;
  }

  // Get list of customers who have sent messages to admin
  async getChatCustomers(): Promise<any[]> {
    // Get the latest message from each customer
    const latestMessages = await db
      .select({
        customerId: chatMessages.senderId,
        maxTime: drizzleSql<string>`max(${chatMessages.createdAt})`.as('max_time')
      })
      .from(chatMessages)
      .innerJoin(users, eq(chatMessages.senderId, users.id))
      .where(and(
        eq(users.role, 'customer'),
        eq(chatMessages.isDeleted, false)
      ))
      .groupBy(chatMessages.senderId);

    // Then get full details for each customer
    const result: any[] = [];
    for (const item of latestMessages) {
      const customerMessages = await db.select({
        customerId: chatMessages.senderId,
        customer: {
          id: users.id,
          name: users.name,
          email: users.email,
          avatar: users.avatar,
        },
        lastMessage: chatMessages.message,
        lastMessageTime: chatMessages.createdAt,
      })
      .from(chatMessages)
      .innerJoin(users, eq(chatMessages.senderId, users.id))
      .where(and(
        eq(chatMessages.senderId, item.customerId),
        drizzleSql`${chatMessages.createdAt} = ${item.maxTime}::timestamp`,
        eq(chatMessages.isDeleted, false)
      ))
      .limit(1);

      if (customerMessages.length > 0) {
        // Get unread count
        const unreadCount = await db.select({
          count: drizzleSql<number>`count(*)`.as('count')
        })
        .from(chatMessages)
        .where(and(
          eq(chatMessages.senderId, item.customerId),
          eq(chatMessages.isRead, false),
          eq(chatMessages.isDeleted, false)
        ));

        result.push({
          ...customerMessages[0],
          unreadCount: unreadCount[0]?.count || 0
        });
      }
    }
    
    return result.sort((a, b) => new Date(b.lastMessageTime).getTime() - new Date(a.lastMessageTime).getTime());
  }

  // Get messages for a specific conversation between admin and customer
  async getConversationMessages(customerId: string, adminId: string): Promise<ChatMessage[]> {
    return await db.select({
      id: chatMessages.id,
      senderId: chatMessages.senderId,
      receiverId: chatMessages.receiverId,
      orderId: chatMessages.orderId,
      message: chatMessages.message,
      type: chatMessages.type,
      isRead: chatMessages.isRead,
      isEdited: chatMessages.isEdited,
      isDeleted: chatMessages.isDeleted,
      editedAt: chatMessages.editedAt,
      deletedAt: chatMessages.deletedAt,
      createdAt: chatMessages.createdAt,
      sender: {
        id: users.id,
        name: users.name,
        role: users.role,
      }
    })
    .from(chatMessages)
    .innerJoin(users, eq(chatMessages.senderId, users.id))
    .where(and(
      or(
        and(eq(chatMessages.senderId, customerId), eq(chatMessages.receiverId, adminId)),
        and(eq(chatMessages.senderId, adminId), eq(chatMessages.receiverId, customerId))
      ),
      eq(chatMessages.isDeleted, false)
    ))
    .orderBy(chatMessages.createdAt);
  }

  async getUserNotifications(userId: string): Promise<Notification[]> {
    return await db.select().from(notifications)
      .where(eq(notifications.userId, userId))
      .orderBy(desc(notifications.createdAt));
  }

  async getUnreadOrderNotificationsCount(userId: string): Promise<number> {
    const result = await db.select({
      count: count(notifications.id)
    })
    .from(notifications)
    .where(and(
      eq(notifications.userId, userId),
      eq(notifications.type, 'order_update'),
      eq(notifications.isRead, false)
    ));

    return Number(result[0]?.count) || 0;
  }

  async markAllNotificationsAsRead(userId: string): Promise<number> {
    const result = await db.update(notifications)
      .set({ isRead: true })
      .where(and(
        eq(notifications.userId, userId),
        eq(notifications.isRead, false)
      ))
      .returning();

    return result.length;
  }

  async markGeneralNotificationsAsRead(userId: string): Promise<number> {
    const result = await db.update(notifications)
      .set({ isRead: true })
      .where(and(
        eq(notifications.userId, userId),
        eq(notifications.isRead, false),
        ne(notifications.type, 'order_update') // Exclude order notifications
      ))
      .returning();

    return result.length;
  }

  async createNotification(notification: InsertNotification): Promise<Notification> {
    const result = await db.insert(notifications).values(notification).returning();
    return result[0];
  }

  async markNotificationAsRead(id: string, userId: string): Promise<boolean> {
    const result = await db.update(notifications)
      .set({ isRead: true })
      .where(and(
        eq(notifications.id, id),
        eq(notifications.userId, userId) // Ensure user can only mark their own notifications as read
      ))
      .returning();
    return result.length > 0;
  }

  async deleteNotification(id: string, userId: string): Promise<boolean> {
    const result = await db.delete(notifications)
      .where(and(
        eq(notifications.id, id),
        eq(notifications.userId, userId) // Ensure user can only delete their own notifications
      ))
      .returning();
    return result.length > 0;
  }

  async getDashboardStats(): Promise<{
    totalSales: number;
    totalOrders: number;
    pendingOrders: number;
    activeCustomers: number;
  }> {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Get online orders stats
    const [onlineSalesResult] = await db.select({
      totalSales: sum(orders.totalAmount),
      totalOrders: count(orders.id),
    }).from(orders).where(eq(orders.status, 'delivered'));

    // Get physical sales stats
    const [physicalSalesResult] = await db.select({
      totalSales: sum(physicalSales.totalAmount),
      totalOrders: count(physicalSales.id),
    }).from(physicalSales);

    // Combine online and physical sales
    const totalOnlineSales = Number(onlineSalesResult?.totalSales) || 0;
    const totalOnlineOrders = Number(onlineSalesResult?.totalOrders) || 0;
    const totalPhysicalSales = Number(physicalSalesResult?.totalSales) || 0;
    const totalPhysicalOrders = Number(physicalSalesResult?.totalOrders) || 0;

    const [pendingResult] = await db.select({
      pendingOrders: count(orders.id),
    }).from(orders).where(eq(orders.status, 'pending'));

    const [customersResult] = await db.select({
      activeCustomers: count(users.id),
    }).from(users).where(eq(users.role, 'customer'));

    return {
      totalSales: totalOnlineSales + totalPhysicalSales,
      totalOrders: totalOnlineOrders + totalPhysicalOrders,
      pendingOrders: Number(pendingResult.pendingOrders) || 0,
      activeCustomers: Number(customersResult.activeCustomers) || 0,
    };
  }

  async getOrderDetailsForReceipt(orderId: string, userId: string): Promise<any> {
    const result = await db.select({
      order: {
        id: orders.id,
        orderNumber: orders.orderNumber,
        createdAt: orders.createdAt,
        deliveredAt: orders.deliveredAt,
        quantity: orders.quantity,
        type: orders.type,
        unitPrice: orders.unitPrice,
        totalAmount: orders.totalAmount,
        paymentMethod: orders.paymentMethod,
        paymentStatus: orders.paymentStatus,
        status: orders.status,
        notes: orders.notes,
      },
      product: {
        name: products.name,
        weight: products.weight,
      },
      customer: {
        name: users.name,
        email: users.email,
        phone: users.phone,
      },
      address: {
        street: addresses.street,
        city: addresses.city,
        province: addresses.province,
        zipCode: addresses.zipCode,
      }
    })
    .from(orders)
    .innerJoin(users, eq(orders.customerId, users.id))
    .leftJoin(products, eq(orders.productId, products.id))
    .leftJoin(addresses, eq(orders.addressId, addresses.id))
    .where(and(
      eq(orders.id, orderId),
      eq(orders.customerId, userId) // Ensure user can only access their own orders
    ))
    .limit(1);

    if (result.length === 0) {
      return null;
    }

    return result[0];
  }

  // Delivery Schedules
  async getDeliverySchedules(userId: string): Promise<any[]> {
    const result = await db.select({
      id: deliverySchedules.id,
      userId: deliverySchedules.userId,
      productId: deliverySchedules.productId,
      addressId: deliverySchedules.addressId,
      name: deliverySchedules.name,
      quantity: deliverySchedules.quantity,
      type: deliverySchedules.type,
      frequency: deliverySchedules.frequency,
      dayOfWeek: deliverySchedules.dayOfWeek,
      dayOfMonth: deliverySchedules.dayOfMonth,
      nextDelivery: deliverySchedules.nextDelivery,
      isActive: deliverySchedules.isActive,
      createdAt: deliverySchedules.createdAt,
      updatedAt: deliverySchedules.updatedAt,
      product: {
        id: products.id,
        name: products.name,
        weight: products.weight,
        newPrice: products.newPrice,
        swapPrice: products.swapPrice,
      },
      address: {
        id: addresses.id,
        street: addresses.street,
        city: addresses.city,
        province: addresses.province,
        zipCode: addresses.zipCode,
      }
    })
    .from(deliverySchedules)
    .leftJoin(products, eq(deliverySchedules.productId, products.id))
    .leftJoin(addresses, eq(deliverySchedules.addressId, addresses.id))
    .where(eq(deliverySchedules.userId, userId))
    .orderBy(desc(deliverySchedules.createdAt));

    return result;
  }

  async getAllDeliverySchedules(): Promise<DeliverySchedule[]> {
    return await db.select().from(deliverySchedules)
      .orderBy(desc(deliverySchedules.nextDelivery));
  }

  async getDeliveryScheduleById(id: string): Promise<DeliverySchedule | undefined> {
    const result = await db.select().from(deliverySchedules)
      .where(eq(deliverySchedules.id, id))
      .limit(1);
    return result[0];
  }

  async createDeliverySchedule(schedule: InsertDeliverySchedule): Promise<DeliverySchedule> {
    const result = await db.insert(deliverySchedules)
      .values(schedule)
      .returning();
    return result[0];
  }

  async updateDeliverySchedule(id: string, updates: Partial<InsertDeliverySchedule>): Promise<DeliverySchedule | undefined> {
    const result = await db.update(deliverySchedules)
      .set({
        ...updates,
        updatedAt: new Date(),
      })
      .where(eq(deliverySchedules.id, id))
      .returning();
    return result[0];
  }

  async deleteDeliverySchedule(id: string): Promise<boolean> {
    const result = await db.delete(deliverySchedules)
      .where(eq(deliverySchedules.id, id))
      .returning();
    return result.length > 0;
  }

  async updateUserEmailVerification(id: string, verified: boolean): Promise<User | undefined> {
    const result = await db.update(users)
      .set({
        emailVerified: verified,
        emailVerificationToken: null,
        emailVerificationExpires: null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
    return result[0];
  }

  async setEmailVerificationToken(id: string, token: string, expires: Date): Promise<User | undefined> {
    const result = await db.update(users)
      .set({
        emailVerificationToken: token,
        emailVerificationExpires: expires,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
    return result[0];
  }

  async getUserByVerificationToken(token: string): Promise<User | undefined> {
    const result = await db.select()
      .from(users)
      .where(and(
        eq(users.emailVerificationToken, token),
        gt(users.emailVerificationExpires, new Date())
      ))
      .limit(1);
    return result[0];
  }

  async clearEmailVerificationToken(id: string): Promise<User | undefined> {
    const result = await db.update(users)
      .set({
        emailVerificationToken: null,
        emailVerificationExpires: null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
    return result[0];
  }

  async setPasswordResetToken(id: string, token: string, expires: Date): Promise<User | undefined> {
    const result = await db.update(users)
      .set({
        passwordResetToken: token,
        passwordResetExpires: expires,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
    return result[0];
  }

  async getUserByPasswordResetToken(token: string): Promise<User | undefined> {
    const result = await db.select()
      .from(users)
      .where(and(
        eq(users.passwordResetToken, token),
        gt(users.passwordResetExpires, new Date())
      ))
      .limit(1);
    return result[0];
  }

  async clearPasswordResetToken(id: string): Promise<User | undefined> {
    const result = await db.update(users)
      .set({
        passwordResetToken: null,
        passwordResetExpires: null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
    return result[0];
  }

  // Delivery Drivers
  async getDeliveryDrivers(): Promise<any[]> {
    return await db.select().from(deliveryDrivers).orderBy(desc(deliveryDrivers.createdAt));
  }

  async createDeliveryDriver(driver: any): Promise<any> {
    const result = await db.insert(deliveryDrivers).values(driver).returning();
    return result[0];
  }

  async updateDeliveryDriver(id: string, updates: any): Promise<any> {
    const result = await db.update(deliveryDrivers)
      .set({
        ...updates,
        updatedAt: new Date(),
      })
      .where(eq(deliveryDrivers.id, id))
      .returning();
    return result[0];
  }

  async deleteDeliveryDriver(id: string): Promise<boolean> {
    const result = await db.delete(deliveryDrivers)
      .where(eq(deliveryDrivers.id, id))
      .returning();
    return result.length > 0;
  }

  async createPosSale(saleData: any): Promise<Order[]> {
    return await db.transaction(async (tx) => {
        const createdOrders: Order[] = [];

        // Get walk-in customer ID if no customer specified
        let customerId = saleData.customerId;
        if (!customerId) {
            const walkInCustomer = await tx.select().from(users).where(eq(users.email, 'walk-in@customer.local')).limit(1);
            if (walkInCustomer.length > 0) {
                customerId = walkInCustomer[0].id;
            } else {
                throw new Error('Walk-in customer user not found. Please run database seeding.');
            }
        }

        for (const item of saleData.items) {
            const productResult = await tx.select().from(products).where(eq(products.id, item.productId)).for('update').limit(1);

            if (productResult.length === 0) {
                throw new Error(`Product with id ${item.productId} not found`);
            }
            const product = productResult[0];

            // Only check and reduce stock for 'new' type items, not 'swap'
            if (item.type === 'new') {
                if (product.stock < item.quantity) {
                    throw new Error(`Insufficient stock for ${product.name}. Only ${product.stock} units available.`);
                }

                const newStock = product.stock - item.quantity;
                await tx.update(products).set({ stock: newStock }).where(eq(products.id, item.productId));
            }

            const timestamp = Date.now();
            const randomSuffix = Math.random().toString(36).substring(2, 5).toUpperCase();
            const orderNumber = `GF-${product.name} ${timestamp}-${randomSuffix}`;

            const unitPrice = item.type === 'new' ? parseFloat(product.newPrice) : parseFloat(product.swapPrice);
            const totalAmount = item.quantity * unitPrice;

            const orderData = {
                customerId,
                productId: item.productId,
                addressId: saleData.addressId,
                quantity: item.quantity,
                type: item.type,
                unitPrice: unitPrice.toString(),
                costPrice: product.wholesalePrice,
                totalAmount: totalAmount.toString(),
                status: "delivered",
                paymentMethod: saleData.paymentMethod,
                notes: `POS Sale - ${saleData.paymentMethod}${saleData.paymentMethod === 'cash' ? ` | Paid: ₱${saleData.amountPaid} | Change: ₱${saleData.change}` : ''}`
            };

            const newOrder = await tx.insert(orders).values({
                ...orderData,
                orderNumber,
            }).returning();

            createdOrders.push(newOrder[0]);
        }
        return createdOrders;
    });
  }

  // Physical Sales
  async getPhysicalSales(): Promise<any[]> {
    const result = await db.select({
      id: physicalSales.id,
      productId: physicalSales.productId,
      type: physicalSales.type,
      quantity: physicalSales.quantity,
      unitPrice: physicalSales.unitPrice,
      totalAmount: physicalSales.totalAmount,
      customerName: physicalSales.customerName,
      customerPhone: physicalSales.customerPhone,
      notes: physicalSales.notes,
      createdAt: physicalSales.createdAt,
      product: {
        id: products.id,
        name: products.name,
        weight: products.weight,
        newPrice: products.newPrice,
        swapPrice: products.swapPrice,
      }
    })
    .from(physicalSales)
    .innerJoin(products, eq(physicalSales.productId, products.id))
    .orderBy(desc(physicalSales.createdAt));

    return result;
  }



  async createPhysicalSaleAndUpdateStock(sale: InsertPhysicalSale): Promise<PhysicalSale> {
    return await db.transaction(async (tx) => {
      const productResult = await tx.select().from(products).where(eq(products.id, sale.productId)).for('update').limit(1);

      if (productResult.length === 0) {
        throw new Error("Product not found");
      }
      const product = productResult[0];

      // Only check and reduce stock for 'new' type sales, not 'swap'
      if (sale.type === 'new') {
        if (product.stock < (sale.quantity || 0)) {
          throw new Error(`Insufficient stock for ${product.name}. Only ${product.stock} units available.`);
        }

        const newStock = product.stock - (sale.quantity || 0);
        await tx.update(products).set({ stock: newStock }).where(eq(products.id, sale.productId));
      }

      const newSale = await tx.insert(physicalSales).values(sale).returning();

      return newSale[0];
    });
  }

  // Payment QR Codes
  async getPaymentQrCodes(): Promise<PaymentQrCode[]> {
    return await db.select().from(paymentQrCodes).orderBy(desc(paymentQrCodes.createdAt));
  }

  async createPaymentQrCode(qrCode: InsertPaymentQrCode): Promise<PaymentQrCode> {
    const result = await db.insert(paymentQrCodes).values(qrCode).returning();
    return result[0];
  }

  async updatePaymentQrCode(id: string, updates: Partial<InsertPaymentQrCode>): Promise<PaymentQrCode | undefined> {
    const result = await db.update(paymentQrCodes)
      .set({
        ...updates,
        updatedAt: new Date(),
      })
      .where(eq(paymentQrCodes.id, id))
      .returning();
    return result[0];
  }

  async deletePaymentQrCode(id: string): Promise<boolean> {
    const result = await db.delete(paymentQrCodes)
      .where(eq(paymentQrCodes.id, id))
      .returning();
    return result.length > 0;
  }

  async seedData(): Promise<void> {
    try {
      // Test database connection with a simple query
      const testResult = await db.select().from(users).limit(1);
      console.log('Database connection test:', testResult.length, 'users found');
      
      // Create admin user
      const adminResult = await db.select().from(users).where(eq(users.email, 'admin@gasflow.com')).limit(1);
      if (adminResult.length === 0) {
        const adminUser = await this.createUser({
          email: 'admin@gasflow.com',
          password: 'admin123',
          name: 'Admin User',
          role: 'admin',
          phone: '+63 912 345 6789',
        });
        // Mark admin as email verified
        await this.updateUserEmailVerification(adminUser.id, true);
        console.log('Admin user created and verified');
      } else {
        console.log('Admin user already exists');
      }
    } catch (error) {
      console.error('Database connection or seeding error:', error);
      // Don't throw error, let app continue running
      return;
    }

    // Create walk-in customer user for POS sales
    const walkInCustomerExists = await this.getUserByEmail('walk-in@customer.local');
    if (!walkInCustomerExists) {
      const walkInUser = await this.createUser({
        email: 'walk-in@customer.local',
        password: 'walkin123', // This password should never be used
        name: 'Walk-in Customer',
        role: 'customer',
        phone: null,
      });
      // Mark as email verified
      await this.updateUserEmailVerification(walkInUser.id, true);
      console.log('Walk-in customer user created');
    }

    // Create sample customer
    const customerExists = await this.getUserByEmail('customer@demo.com');
    let customerId: string;

    if (!customerExists) {
      const customerUser = await this.createUser({
        email: 'customer@demo.com',
        password: 'demo123',
        name: 'John Doe',
        role: 'customer',
        phone: '+63 917 123 4567',
      });
      // Mark customer as email verified
      await this.updateUserEmailVerification(customerUser.id, true);
      customerId = customerUser.id;
    } else {
      customerId = customerExists.id;
    }

    // Create sample addresses for demo customer
    const existingAddresses = await this.getUserAddresses(customerId);
    if (existingAddresses.length === 0) {
      // Create sample delivery drivers
      const existingDrivers = await this.getDeliveryDrivers();
      if (existingDrivers.length === 0) {
        await this.createDeliveryDriver({
          name: 'Juan Dela Cruz',
          phone: '+63 912 345 6789',
          email: 'juan.delacruz@gasflow.com',
          licenseNumber: 'ABC-123-XYZ',
          vehicleType: 'motorcycle',
          plateNumber: 'XYZ-456',
          rating: '4.8',
          isActive: true,
        });
  
        await this.createDeliveryDriver({
          name: 'Maria Santos',
          phone: '+63 917 987 6543',
          email: 'maria.santos@gasflow.com',
          licenseNumber: 'DEF-456-UVW',
          vehicleType: 'van',
          plateNumber: 'UVW-789',
          rating: '4.9',
          isActive: true,
        });
  
        await this.createDeliveryDriver({
          name: 'Pedro Reyes',
          phone: '+63 918 555 1234',
          email: 'pedro.reyes@gasflow.com',
          licenseNumber: 'GHI-789-RST',
          vehicleType: 'motorcycle',
          plateNumber: 'RST-012',
          rating: '4.7',
          isActive: true,
        });
  
        console.log('Sample delivery drivers created');
      }
  
    }

  }
}

export const storage = new DrizzleStorage();
