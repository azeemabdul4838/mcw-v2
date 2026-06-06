const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();

// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'mcw-super-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ─── DATABASE ─────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/mcw_store')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('❌ MongoDB error:', err));

// ══════════════════════════════════════════════════════════════
//  MODELS
// ══════════════════════════════════════════════════════════════

// User
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  email:     { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  role:      { type: String, default: 'customer' },
  phone:     { type: String },
  address:   { type: String },
  razorpayContactId:  { type: String },
  razorpayFundId:     { type: String },
  bankName:           { type: String },
  bankAccountNumber:  { type: String },
  bankIFSC:           { type: String },
  bankLinked:         { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Product
const productSchema = new mongoose.Schema({
  name:        { type: String, required: true },
  category:    { type: String, required: true },
  price:       { type: Number, required: true },
  originalPrice: { type: Number },
  description: { type: String },
  image:       { type: String, default: '' },
  stock:       { type: Number, default: 100 },
  tag:         { type: String },
  type:        { type: String, default: 'own' },
  affiliatePlatform: { type: String },
  affiliateUrl:      { type: String },
  affiliateCommission: { type: String },
  active:      { type: Boolean, default: true },
  createdAt:   { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);

// Order
const orderSchema = new mongoose.Schema({
  user:            { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  guestEmail:      { type: String },
  items:           [{ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, name: String, price: Number, qty: Number }],
  total:           { type: Number, required: true },
  status:          { type: String, default: 'pending' },
  address:         { type: String },
  phone:           { type: String },
  razorpayOrderId:   { type: String },
  razorpayPaymentId: { type: String },
  createdAt:       { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// Blog Post
const blogSchema = new mongoose.Schema({
  title:       { type: String, required: true },
  slug:        { type: String, required: true, unique: true },
  excerpt:     { type: String },
  content:     { type: String },
  category:    { type: String, default: 'Style Tips' },
  image:       { type: String, default: '' },
  published:   { type: Boolean, default: true },
  createdAt:   { type: Date, default: Date.now }
});
const Blog = mongoose.model('Blog', blogSchema);

// ─── RAZORPAY ─────────────────────────────────────────────────
const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID     || 'YOUR_RAZORPAY_KEY_ID',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'YOUR_RAZORPAY_KEY_SECRET'
});

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────
const requireLogin = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Please log in first' });
  next();
};
const requireAdmin = async (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const user = await User.findById(req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Admin access only' });
  req.adminUser = user;
  next();
};

// ══════════════════════════════════════════════════════════════
//  PAGES
// ══════════════════════════════════════════════════════════════
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ══════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed, phone });
    req.session.userId = user._id;
    res.json({ message: 'Registered!', user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid email or password' });
    req.session.userId = user._id;
    res.json({ message: 'Logged in', user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/logout', (req, res) => { req.session.destroy(); res.json({ message: 'Logged out' }); });

app.get('/api/auth/me', requireLogin, async (req, res) => {
  const user = await User.findById(req.session.userId).select('-password');
  res.json(user);
});

app.put('/api/auth/profile', requireLogin, async (req, res) => {
  try {
    const { name, phone, address } = req.body;
    const user = await User.findByIdAndUpdate(req.session.userId, { name, phone, address }, { new: true }).select('-password');
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── CHANGE ADMIN PASSWORD ────────────────────────────────────
app.post('/api/admin/change-password', requireAdmin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.session.userId);
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.status(400).json({ error: 'Current password is incorrect' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.session.userId, { password: hashed });
    res.json({ message: '✅ Password changed successfully!' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
//  PRODUCT ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/products', async (req, res) => {
  try {
    const filter = { active: true };
    if (req.query.category) filter.category = req.query.category;
    if (req.query.type) filter.type = req.query.type;
    const products = await Product.find(filter).sort({ createdAt: -1 });
    res.json(products);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json(product);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Add product — Admin only
app.post('/api/products', requireAdmin, async (req, res) => {
  try {
    const product = await Product.create(req.body);
    res.status(201).json(product);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update product — Admin only
app.put('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(product);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete product permanently — Admin only
app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: '✅ Product deleted permanently' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Toggle product active/inactive — Admin only
app.patch('/api/products/:id/toggle', requireAdmin, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    product.active = !product.active;
    await product.save();
    res.json({ message: `Product ${product.active ? 'activated' : 'deactivated'}`, active: product.active });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
//  BLOG ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/blogs', async (req, res) => {
  try {
    const blogs = await Blog.find({ published: true }).sort({ createdAt: -1 });
    res.json(blogs);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/blogs/:slug', async (req, res) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug, published: true });
    if (!blog) return res.status(404).json({ error: 'Blog post not found' });
    res.json(blog);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Add blog — Admin only
app.post('/api/blogs', requireAdmin, async (req, res) => {
  try {
    const { title, excerpt, content, category, image } = req.body;
    const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    const blog = await Blog.create({ title, slug, excerpt, content, category, image });
    res.status(201).json(blog);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update blog — Admin only
app.put('/api/blogs/:id', requireAdmin, async (req, res) => {
  try {
    const blog = await Blog.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(blog);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete blog — Admin only
app.delete('/api/blogs/:id', requireAdmin, async (req, res) => {
  try {
    await Blog.findByIdAndDelete(req.params.id);
    res.json({ message: '✅ Blog post deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
//  ORDER & PAYMENT ROUTES
// ══════════════════════════════════════════════════════════════
app.post('/api/orders/create', async (req, res) => {
  try {
    const { items, address, phone, guestEmail } = req.body;
    if (!items || items.length === 0) return res.status(400).json({ error: 'Cart is empty' });

    let total = 0;
    const orderItems = [];
    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product) return res.status(404).json({ error: 'Product not found' });
      total += product.price * item.qty;
      orderItems.push({ product: product._id, name: product.name, price: product.price, qty: item.qty });
    }

    const razorpayOrder = await razorpay.orders.create({
      amount: total * 100,
      currency: 'INR',
      receipt: `mcw_${Date.now()}`
    });

    const orderData = { items: orderItems, total, address, phone, razorpayOrderId: razorpayOrder.id, status: 'pending' };
    if (req.session.userId) orderData.user = req.session.userId;
    else orderData.guestEmail = guestEmail;

    const order = await Order.create(orderData);
    res.json({ orderId: order._id, razorpayOrderId: razorpayOrder.id, amount: razorpayOrder.amount, currency: razorpayOrder.currency, key: process.env.RAZORPAY_KEY_ID || 'YOUR_RAZORPAY_KEY_ID' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/orders/verify', async (req, res) => {
  try {
    const { razorpayOrderId, razorpayPaymentId, razorpaySignature, orderId } = req.body;
    const body = razorpayOrderId + '|' + razorpayPaymentId;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'YOUR_RAZORPAY_KEY_SECRET').update(body).digest('hex');
    if (expected !== razorpaySignature) return res.status(400).json({ error: 'Payment verification failed' });
    await Order.findByIdAndUpdate(orderId, { status: 'paid', razorpayPaymentId });
    res.json({ message: '✅ Payment verified! Order confirmed.' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/orders/mine', requireLogin, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.session.userId }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════════════════════════

// Dashboard stats
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const totalOrders    = await Order.countDocuments();
    const paidOrders     = await Order.countDocuments({ status: 'paid' });
    const revenueResult  = await Order.aggregate([{ $match: { status: 'paid' } }, { $group: { _id: null, total: { $sum: '$total' } } }]);
    const totalRevenue   = revenueResult[0]?.total || 0;
    const totalCustomers = await User.countDocuments({ role: 'customer' });
    const totalProducts  = await Product.countDocuments({ active: true });
    const totalBlogs     = await Blog.countDocuments({ published: true });
    const recentOrders   = await Order.find().sort({ createdAt: -1 }).limit(5).populate('user', 'name email');
    res.json({ totalOrders, paidOrders, totalRevenue, totalCustomers, totalProducts, totalBlogs, recentOrders });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// All orders
app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  try {
    const orders = await Order.find().populate('user', 'name email').sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update order status
app.put('/api/admin/orders/:id', requireAdmin, async (req, res) => {
  try {
    const order = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    res.json(order);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// All customers
app.get('/api/admin/customers', requireAdmin, async (req, res) => {
  try {
    const customers = await User.find({ role: 'customer' }).select('-password').sort({ createdAt: -1 });
    res.json(customers);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// All products including inactive
app.get('/api/admin/products', requireAdmin, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// All blogs
app.get('/api/admin/blogs', requireAdmin, async (req, res) => {
  try {
    const blogs = await Blog.find().sort({ createdAt: -1 });
    res.json(blogs);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Create first admin (only works if no admin exists)
app.post('/api/setup/admin', async (req, res) => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) return res.status(400).json({ error: 'Admin already exists' });
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const admin = await User.create({ name, email, password: hashed, role: 'admin' });
    res.json({ message: '✅ Admin created!', email: admin.email });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── START ────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 MCW running at http://localhost:${PORT}`));
