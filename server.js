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
  secret: 'mcw-super-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ─── DATABASE ─────────────────────────────────────────────────
mongoose.connect('mongodb://localhost:27017/mcw_store')
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
  // Razorpay linked account (for payouts)
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
  type:        { type: String, default: 'own' }, // 'own' or 'affiliate'
  // Affiliate specific
  affiliatePlatform: { type: String }, // 'amazon', 'myntra', 'flipkart'
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

// Update profile & address
app.put('/api/auth/profile', requireLogin, async (req, res) => {
  try {
    const { name, phone, address } = req.body;
    const user = await User.findByIdAndUpdate(req.session.userId, { name, phone, address }, { new: true }).select('-password');
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
//  BANK ACCOUNT LINKING (via Razorpay Route)
// ══════════════════════════════════════════════════════════════
app.post('/api/auth/link-bank', requireLogin, async (req, res) => {
  try {
    const { bankName, accountNumber, ifsc, accountHolder } = req.body;
    if (!bankName || !accountNumber || !ifsc || !accountHolder)
      return res.status(400).json({ error: 'All bank details required' });

    // Create Razorpay Contact
    const contact = await razorpay.contacts.create({
      name: accountHolder,
      type: 'customer',
      reference_id: req.session.userId.toString()
    });

    // Create Fund Account (bank account)
    const fundAccount = await razorpay.fundAccount.create({
      contact_id: contact.id,
      account_type: 'bank_account',
      bank_account: {
        name: accountHolder,
        ifsc: ifsc,
        account_number: accountNumber
      }
    });

    // Save to user
    await User.findByIdAndUpdate(req.session.userId, {
      razorpayContactId: contact.id,
      razorpayFundId: fundAccount.id,
      bankName,
      bankAccountNumber: accountNumber.slice(-4), // save only last 4 digits
      bankIFSC: ifsc,
      bankLinked: true
    });

    res.json({ message: 'Bank account linked successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Bank linking failed: ' + err.message });
  }
});

// Get bank status
app.get('/api/auth/bank-status', requireLogin, async (req, res) => {
  const user = await User.findById(req.session.userId).select('bankLinked bankName bankAccountNumber bankIFSC');
  res.json(user);
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

// Delete product — Admin only
app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    await Product.findByIdAndUpdate(req.params.id, { active: false });
    res.json({ message: 'Product removed' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
//  ORDER & PAYMENT ROUTES
// ══════════════════════════════════════════════════════════════

// Create Razorpay order
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

    const orderData = {
      items: orderItems,
      total,
      address,
      phone,
      razorpayOrderId: razorpayOrder.id,
      status: 'pending'
    };
    if (req.session.userId) orderData.user = req.session.userId;
    else orderData.guestEmail = guestEmail;

    const order = await Order.create(orderData);

    res.json({
      orderId: order._id,
      razorpayOrderId: razorpayOrder.id,
      amount: razorpayOrder.amount,
      currency: razorpayOrder.currency,
      key: process.env.RAZORPAY_KEY_ID || 'YOUR_RAZORPAY_KEY_ID'
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Verify payment
app.post('/api/orders/verify', async (req, res) => {
  try {
    const { razorpayOrderId, razorpayPaymentId, razorpaySignature, orderId } = req.body;
    const body = razorpayOrderId + '|' + razorpayPaymentId;
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'YOUR_RAZORPAY_KEY_SECRET')
      .update(body).digest('hex');
    if (expected !== razorpaySignature) return res.status(400).json({ error: 'Payment verification failed' });
    await Order.findByIdAndUpdate(orderId, { status: 'paid', razorpayPaymentId });
    res.json({ message: '✅ Payment verified! Order confirmed.' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// My orders
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
    const recentOrders   = await Order.find().sort({ createdAt: -1 }).limit(5).populate('user', 'name email');
    res.json({ totalOrders, paidOrders, totalRevenue, totalCustomers, totalProducts, recentOrders });
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

// All products (including inactive)
app.get('/api/admin/products', requireAdmin, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── START ────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 MCW running at http://localhost:${PORT}`));
