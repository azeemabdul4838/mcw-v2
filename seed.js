// Run once: node seed.js
// Creates admin account + sample products

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

mongoose.connect('mongodb://localhost:27017/mcw_store')
  .then(() => console.log('Connected...'))
  .catch(err => { console.log(err); process.exit(1); });

const userSchema = new mongoose.Schema({ name:String, email:String, password:String, role:String, phone:String, bankLinked:Boolean, createdAt:{type:Date,default:Date.now} });
const productSchema = new mongoose.Schema({ name:String, category:String, price:Number, originalPrice:Number, description:String, image:String, stock:Number, tag:String, type:String, affiliatePlatform:String, affiliateUrl:String, affiliateCommission:String, active:{type:Boolean,default:true}, createdAt:{type:Date,default:Date.now} });

const User    = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);

async function seed() {
  // Create admin
  const existing = await User.findOne({ email: 'admin@mcw.com' });
  if (!existing) {
    const hashed = await bcrypt.hash('admin123', 10);
    await User.create({ name: 'MCW Admin', email: 'admin@mcw.com', password: hashed, role: 'admin' });
    console.log('✅ Admin created — email: admin@mcw.com | password: admin123');
  } else {
    console.log('ℹ️  Admin already exists');
  }

  // Products
  await Product.deleteMany({});
  await Product.insertMany([
    // Own products
    { name:'Urban Drop Tee',    category:'T-Shirts', price:899,  originalPrice:1299, stock:50,  tag:'Hot',  type:'own',  description:'Bold streetwear graphic tee, 100% cotton.' },
    { name:'Block Bomber',      category:'Jackets',  price:2499, originalPrice:3499, stock:30,  tag:'New',  type:'own',  description:'Premium bomber jacket with clean block design.' },
    { name:'Core Hoodie',       category:'Hoodies',  price:1799, originalPrice:2299, stock:40,  tag:null,   type:'own',  description:'Everyday essential hoodie, fleece lined.' },
    { name:'Flex Jogger',       category:'Joggers',  price:1299, originalPrice:1799, stock:60,  tag:'Sale', type:'own',  description:'Slim-fit jogger pants with side pockets.' },
    // Affiliate products
    { name:'Nike Dri-FIT Tee',  category:'T-Shirts', price:1299, stock:0, tag:'Hot', type:'affiliate', affiliatePlatform:'amazon',  affiliateUrl:'https://www.amazon.in/s?k=nike+dri+fit+tshirt&tag=YOUR-TAG-21', affiliateCommission:'9%',  description:'Best-selling Nike performance tee. Buy on Amazon.' },
    { name:'Roadster Hoodie',   category:'Hoodies',  price:999,  stock:0, tag:'New', type:'affiliate', affiliatePlatform:'myntra',  affiliateUrl:'https://www.myntra.com/hoodies', affiliateCommission:'10%', description:'Myntra bestselling hoodie brand. Great quality.' },
    { name:"Men's Joggers",     category:'Joggers',  price:849,  stock:0, tag:null,  type:'affiliate', affiliatePlatform:'flipkart', affiliateUrl:'https://www.flipkart.com/mens-joggers', affiliateCommission:'10%', description:'Top rated joggers on Flipkart.' },
  ]);
  console.log('✅ Products seeded!');
  mongoose.disconnect();
}
seed();
