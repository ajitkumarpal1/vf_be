const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_should_be_in_env_in_production';
const WHATSAPP_NUMBER = process.env.WHATSAPP_NUMBER || '919925629486'; // Set via environment variable

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/shopkeeper_db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// User Schema (Shopkeeper)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'shopkeeper' }
});

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    description: { type: String },
    images: [{ type: String }], // Changed from single image to array of images
    category: { type: String },
    inStock: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

// FIXED: Simplified Multer configuration for multiple file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + '-' + file.originalname);
    }
});

// Single multer instance that handles multiple files properly
const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit per file
        files: 5 // Maximum 5 files
    },
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Initialize default shopkeeper (run once)
app.post('/api/init', async (req, res) => {
    try {
        const existingUser = await User.findOne({ username: 'shopkeeper' });
        if (existingUser) {
            return res.json({ message: 'Shopkeeper already exists' });
        }

        const hashedPassword = await bcrypt.hash('shop123', 10);
        const shopkeeper = new User({
            username: 'shopkeeper',
            password: hashedPassword
        });

        await shopkeeper.save();
        res.json({ message: 'Default shopkeeper created with username: shopkeeper, password: shop123' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ token, username: user.username });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Get all products (public)
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// FIXED: Add product with proper error handling
app.post('/api/products', authenticateToken, upload.array('images', 5), async (req, res) => {
    try {
        const { name, price, description, category, inStock } = req.body;
        
        // Validate required fields
        if (!name || name.trim() === '') {
            return res.status(400).json({ message: 'Product name is required' });
        }
        
        if (!price || isNaN(parseFloat(price)) || parseFloat(price) <= 0) {
            return res.status(400).json({ message: 'Valid price is required' });
        }
        
        if (!category || category.trim() === '') {
            return res.status(400).json({ message: 'Category is required' });
        }

        const images = req.files ? req.files.map(file => file.filename) : [];

        const product = new Product({
            name: name.trim(),
            price: parseFloat(price),
            description: description ? description.trim() : '',
            category: category.trim(),
            images,
            inStock: inStock === 'true' || inStock === true
        });

        await product.save();
        res.status(201).json(product);
    } catch (error) {
        console.error('Error adding product:', error);
        
        // Clean up uploaded files if product creation fails
        if (req.files) {
            req.files.forEach(file => {
                const filePath = path.join(__dirname, 'uploads', file.filename);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            });
        }
        
        res.status(500).json({ message: error.message });
    }
});

// FIXED: Update product with proper error handling
app.put('/api/products/:id', authenticateToken, upload.array('images', 5), async (req, res) => {
    try {
        const { name, price, description, category, inStock, keepExistingImages } = req.body;
        
        // Validate required fields
        if (name && name.trim() === '') {
            return res.status(400).json({ message: 'Product name cannot be empty' });
        }
        
        if (price && (isNaN(parseFloat(price)) || parseFloat(price) <= 0)) {
            return res.status(400).json({ message: 'Valid price is required' });
        }
        
        const updateData = {};
        
        if (name) updateData.name = name.trim();
        if (price) updateData.price = parseFloat(price);
        if (description !== undefined) updateData.description = description.trim();
        if (category) updateData.category = category.trim();
        if (inStock !== undefined) updateData.inStock = inStock === 'true' || inStock === true;
        
        // Handle images
        let images = [];
        if (keepExistingImages === 'true') {
            const existingProduct = await Product.findById(req.params.id);
            if (existingProduct && existingProduct.images) {
                images = [...existingProduct.images];
            }
        }
        
        if (req.files && req.files.length > 0) {
            const newImages = req.files.map(file => file.filename);
            images = [...images, ...newImages];
        }
        
        if (images.length > 0 || keepExistingImages !== 'true') {
            updateData.images = images;
        }

        const product = await Product.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true }
        );

        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        res.json(product);
    } catch (error) {
        console.error('Error updating product:', error);
        
        // Clean up uploaded files if update fails
        if (req.files) {
            req.files.forEach(file => {
                const filePath = path.join(__dirname, 'uploads', file.filename);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            });
        }
        
        res.status(500).json({ message: error.message });
    }
});

// Update product stock status (protected)
app.patch('/api/products/:id/stock', authenticateToken, async (req, res) => {
    try {
        const { inStock } = req.body;
        
        if (typeof inStock !== 'boolean') {
            return res.status(400).json({ message: 'inStock must be a boolean value' });
        }

        const product = await Product.findByIdAndUpdate(
            req.params.id,
            { inStock },
            { new: true }
        );

        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        res.json({ 
            message: `Product stock status updated to ${inStock ? 'In Stock' : 'Out of Stock'}`,
            product 
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Delete product (protected) - Clean up multiple images
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // Delete all image files if they exist
        if (product.images && product.images.length > 0) {
            product.images.forEach(imageName => {
                const imagePath = path.join(__dirname, 'uploads', imageName);
                if (fs.existsSync(imagePath)) {
                    fs.unlinkSync(imagePath);
                }
            });
        }

        // Delete the product from database
        await Product.findByIdAndDelete(req.params.id);

        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// WhatsApp availability check endpoint
app.post('/api/check-availability', (req, res) => {
    try {
        const { items, total } = req.body;
        
        if (!items || items.length === 0) {
            return res.status(400).json({ message: 'No items in cart' });
        }
        
        let availabilityMessage = `*Product Availability Check*\n\n`;
        availabilityMessage += `*Items to Check:*\n`;
        
        items.forEach((item, index) => {
            availabilityMessage += `${index + 1}. *${item.name}*\n`;
            availabilityMessage += `   • Quantity: ${item.quantity}\n`;
            availabilityMessage += `   • Price: ₹${item.price} each\n`;
            availabilityMessage += `   • Total: ₹${item.price * item.quantity}\n`;
            if (item.category) {
                availabilityMessage += `   • Category: ${item.category}\n`;
            }
            if (item.description) {
                availabilityMessage += `   • Description: ${item.description.substring(0, 50)}${item.description.length > 50 ? '...' : ''}\n`;
            }
            availabilityMessage += `\n`;
        });
        
        availabilityMessage += `*Estimated Total:* ₹${total}\n\n`;
        availabilityMessage += `_Please confirm availability and final price for these items._\n\n`;
        availabilityMessage += `*Reply with:*\n`;
        availabilityMessage += `✅ "Available" - if all items are in stock\n`;
        availabilityMessage += `❌ "Not Available" - if any item is out of stock\n`;
        availabilityMessage += `📝 "Partial" - if some items are available\n\n`;
        availabilityMessage += `_Thank you!_ 🙏`;
        
        // Generate WhatsApp URL
        const whatsappUrl = `https://wa.me/${WHATSAPP_NUMBER}?text=${encodeURIComponent(availabilityMessage)}`;
        
        console.log('Availability check sent to:', WHATSAPP_NUMBER);
        res.json({ 
            message: 'Availability check sent successfully',
            whatsappUrl,
            checkDetails: availabilityMessage
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Get product details with image for WhatsApp sharing
app.get('/api/product-details/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        
        // Get protocol (http or https) correctly
        const protocol = req.headers['x-forwarded-proto'] || req.protocol;
        const host = req.get('host');
        
        const productDetails = {
            ...product.toObject(),
            imageUrls: product.images ? product.images.map(img => `${protocol}://${host}/uploads/${img}`) : []
        };
        
        res.json(productDetails);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Multer error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File size too large. Maximum 5MB per file allowed.' });
        }
        if (error.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({ message: 'Too many files. Maximum 5 files allowed.' });
        }
        if (error.code === 'LIMIT_UNEXPECTED_FILE') {
            return res.status(400).json({ message: 'Unexpected file field.' });
        }
        return res.status(400).json({ message: `Upload error: ${error.message}` });
    }
    
    if (error.message === 'Only image files are allowed!') {
        return res.status(400).json({ message: 'Only image files are allowed!' });
    }
    
    console.error('Unhandled error:', error);
    res.status(500).json({ message: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ message: 'Endpoint not found' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('First time setup: POST to /api/init to create default shopkeeper');
    console.log(`WhatsApp number set to: ${WHATSAPP_NUMBER}`);
});