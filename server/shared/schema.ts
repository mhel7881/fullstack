import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, decimal, timestamp, boolean, jsonb, uuid } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  role: text("role").notNull().default("customer"), // "customer" | "admin"
  name: text("name").notNull(),
  phone: text("phone"),
  address: text("address"),
  addressCoordinates: jsonb("address_coordinates"), // { lat: number, lng: number }
  avatar: text("avatar"),
  emailVerified: boolean("email_verified").default(false).notNull(),
  emailVerificationToken: text("email_verification_token"),
  emailVerificationExpires: timestamp("email_verification_expires"),
  passwordResetToken: text("password_reset_token"),
  passwordResetExpires: timestamp("password_reset_expires"),
  termsAccepted: boolean("terms_accepted").default(false).notNull(),
  privacyAccepted: boolean("privacy_accepted").default(false).notNull(),
  termsAcceptedAt: timestamp("terms_accepted_at"),
  privacyAcceptedAt: timestamp("privacy_accepted_at"),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`now()`).notNull(),
});

export const addresses = pgTable("addresses", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").references(() => users.id).notNull(),
  label: text("label").notNull(), // "Home", "Work", etc.
  street: text("street").notNull(),
  city: text("city").notNull(),
  province: text("province").notNull(),
  zipCode: text("zip_code").notNull(),
  coordinates: jsonb("coordinates"), // { lat: number, lng: number }
  isDefault: boolean("is_default").default(false),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
});

export const deliverySchedules = pgTable("delivery_schedules", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").references(() => users.id).notNull(),
  productId: uuid("product_id").references(() => products.id).notNull(),
  addressId: uuid("address_id").references(() => addresses.id).notNull(),
  name: text("name").notNull(),
  quantity: integer("quantity").default(1).notNull(),
  type: text("type").notNull(), // "new" | "swap"
  frequency: text("frequency").notNull(), // "weekly" | "biweekly" | "monthly"
  dayOfWeek: integer("day_of_week"), // 0-6 for weekly/biweekly (0=Sunday)
  dayOfMonth: integer("day_of_month"), // 1-31 for monthly
  nextDelivery: timestamp("next_delivery").notNull(),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`now()`).notNull(),
});

export const products = pgTable("products", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  description: text("description"),
  weight: text("weight").notNull(), // "7kg", "11kg", "22kg"
  newPrice: decimal("new_price", { precision: 10, scale: 2 }).notNull(),
  swapPrice: decimal("swap_price", { precision: 10, scale: 2 }).notNull(),
  wholesalePrice: decimal("wholesale_price", { precision: 10, scale: 2 }).default("0").notNull(),
  stock: integer("stock").default(0).notNull(),
  image: text("image"),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`now()`).notNull(),
});

export const orders = pgTable("orders", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  orderNumber: text("order_number").notNull().unique(),
  customerId: uuid("customer_id").references(() => users.id).notNull(),
  productId: uuid("product_id").references(() => products.id).notNull(),
  addressId: uuid("address_id").references(() => addresses.id).notNull(),
  quantity: integer("quantity").default(1).notNull(),
  type: text("type").notNull(), // "new" | "swap"
  unitPrice: decimal("unit_price", { precision: 10, scale: 2 }).notNull(),
  costPrice: decimal("cost_price", { precision: 10, scale: 2 }).default("0").notNull(),
  totalAmount: decimal("total_amount", { precision: 10, scale: 2 }).notNull(),
  status: text("status").default("pending").notNull(), // "pending" | "processing" | "out_for_delivery" | "delivered" | "cancelled"
  paymentMethod: text("payment_method").notNull(), // "cod" | "bank_transfer"
  paymentStatus: text("payment_status").default("pending").notNull(), // "pending" | "paid" | "failed"
  paymentVerificationStatus: text("payment_verification_status"), // "pending" | "verified" | "rejected"
  referenceNumber: text("reference_number"), // For bank transfer payments
  proofOfPayment: text("proof_of_payment"), // URL to uploaded proof of payment image
  submittedAt: timestamp("submitted_at"), // When payment reference was submitted
  verifiedAt: timestamp("verified_at"), // When payment was verified/rejected
  verifiedBy: uuid("verified_by").references(() => users.id), // Admin who verified
  notes: text("notes"),
  scheduledDate: timestamp("scheduled_date"),
  deliveredAt: timestamp("delivered_at"),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`now()`).notNull(),
});

export const cartItems = pgTable("cart_items", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").references(() => users.id).notNull(),
  productId: uuid("product_id").references(() => products.id).notNull(),
  quantity: integer("quantity").default(1).notNull(),
  type: text("type").notNull(), // "new" | "swap"
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
});

export const chatMessages = pgTable("chat_messages", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  senderId: uuid("sender_id").references(() => users.id).notNull(),
  receiverId: uuid("receiver_id").references(() => users.id),
  orderId: uuid("order_id").references(() => orders.id),
  message: text("message").notNull(),
  type: text("type").default("text").notNull(), // "text" | "image" | "system"
  isRead: boolean("is_read").default(false),
  isEdited: boolean("is_edited").default(false),
  isDeleted: boolean("is_deleted").default(false),
  editedAt: timestamp("edited_at"),
  deletedAt: timestamp("deleted_at"),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
});

export const deliveryDrivers = pgTable("delivery_drivers", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  phone: text("phone").notNull(),
  email: text("email"),
  licenseNumber: text("license_number").notNull(),
  vehicleType: text("vehicle_type").notNull(), // "motorcycle", "van", "truck"
  plateNumber: text("plate_number").notNull(),
  rating: decimal("rating", { precision: 3, scale: 2 }).default("4.8"), // 1.0 to 5.0
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`now()`).notNull(),
});

export const notifications = pgTable("notifications", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").references(() => users.id).notNull(),
  title: text("title").notNull(),
  message: text("message").notNull(),
  type: text("type").notNull(), // "order_update" | "promo" | "reminder" | "system"
  data: jsonb("data"), // Additional data like order_id, etc.
  isRead: boolean("is_read").default(false),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
});

// Insert schemas
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  emailVerified: true,
  emailVerificationToken: true,
  emailVerificationExpires: true,
  passwordResetToken: true,
  passwordResetExpires: true,
  termsAcceptedAt: true,
  privacyAcceptedAt: true,
  createdAt: true,
  updatedAt: true,
});

export const insertAddressSchema = createInsertSchema(addresses).omit({
  id: true,
  createdAt: true,
});

export const insertProductSchema = createInsertSchema(products).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertOrderSchema = createInsertSchema(orders).omit({
  id: true,
  orderNumber: true,
  paymentVerificationStatus: true,
  submittedAt: true,
  verifiedAt: true,
  verifiedBy: true,
  createdAt: true,
  updatedAt: true,
});

export const insertCartItemSchema = createInsertSchema(cartItems).omit({
  id: true,
  createdAt: true,
});

export const insertChatMessageSchema = createInsertSchema(chatMessages).omit({
  id: true,
  createdAt: true,
});

export const insertNotificationSchema = createInsertSchema(notifications).omit({
  id: true,
  createdAt: true,
});

export const insertDeliveryDriverSchema = createInsertSchema(deliveryDrivers).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertDeliveryScheduleSchema = createInsertSchema(deliverySchedules).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const physicalSales = pgTable("physical_sales", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  productId: uuid("product_id").references(() => products.id).notNull(),
  type: text("type").notNull(), // "new" | "swap"
  quantity: integer("quantity").default(1).notNull(),
  unitPrice: decimal("unit_price", { precision: 10, scale: 2 }).notNull(),
  totalAmount: decimal("total_amount", { precision: 10, scale: 2 }).notNull(),
  customerName: text("customer_name"),
  customerPhone: text("customer_phone"),
  notes: text("notes"),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
});

export const insertPhysicalSaleSchema = createInsertSchema(physicalSales).omit({
  id: true,
  createdAt: true,
});

export const paymentQrCodes = pgTable("payment_qr_codes", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  type: text("type").notNull(), // "gcash"
  imageUrl: text("image_url").notNull(),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at").default(sql`now()`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`now()`).notNull(),
});

export const insertPaymentQrCodeSchema = createInsertSchema(paymentQrCodes).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

// Login schema
export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

// Types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Address = typeof addresses.$inferSelect;
export type InsertAddress = z.infer<typeof insertAddressSchema>;
export type Product = typeof products.$inferSelect;
export type InsertProduct = z.infer<typeof insertProductSchema>;
export type Order = typeof orders.$inferSelect;
export type InsertOrder = z.infer<typeof insertOrderSchema>;
export type CartItem = typeof cartItems.$inferSelect;
export type InsertCartItem = z.infer<typeof insertCartItemSchema>;
export type ChatMessage = typeof chatMessages.$inferSelect;
export type InsertChatMessage = z.infer<typeof insertChatMessageSchema>;
export type Notification = typeof notifications.$inferSelect;
export type InsertNotification = z.infer<typeof insertNotificationSchema>;
export type DeliveryDriver = typeof deliveryDrivers.$inferSelect;
export type InsertDeliveryDriver = z.infer<typeof insertDeliveryDriverSchema>;
export type DeliverySchedule = typeof deliverySchedules.$inferSelect;
export type InsertDeliverySchedule = z.infer<typeof insertDeliveryScheduleSchema>;
export type PhysicalSale = typeof physicalSales.$inferSelect;
export type InsertPhysicalSale = z.infer<typeof insertPhysicalSaleSchema>;
export type PaymentQrCode = typeof paymentQrCodes.$inferSelect;
export type InsertPaymentQrCode = z.infer<typeof insertPaymentQrCodeSchema>;
export type LoginRequest = z.infer<typeof loginSchema>;
