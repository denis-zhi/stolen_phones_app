const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret'; 

// MongoDB connection string
const MONGO_URI = 'mongodb://localhost:27017/stolen_phones_db';

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Error connecting to MongoDB:', err.message);
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('C:/stolen_phones_app/public'));

app.get('/info', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'info.html'));
});

// Модель телефона
const PhoneSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    brand: String,
    model: String,
    IMEI: String,
    serialNumber: String,
    theftDate: Date,
    status: String,
    
});

const Phone = mongoose.model('Phone', PhoneSchema);

// Модель пользователя
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});

UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

UserSchema.methods.isPasswordMatch = function(password) {
    return bcrypt.compareSync(password, this.password);
};

const User = mongoose.model('User', UserSchema);

// Подключение и конфигурация passport
app.use(passport.initialize());
require('./config/passport')(passport);

// Маршруты

app.get('/public/info.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'info.html'));
});

app.post('/users/register', async (req, res) => {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.status(400).json({ success: false, message: "Email already exists." });
    }

    const user = new User({ email, password });
    await user.save();
    res.json({ success: true, message: "User registered successfully!" });
});

app.post('/users/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !user.isPasswordMatch(password)) {
        return res.status(401).json({ success: false, message: "Invalid email or password." });
    }

    const payload = { id: user.id, email: user.email };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
    console.log("Login successful for:", user.email, "UserId:", user._id);
    console.log(user._id)
    res.json({ success: true, token: `Bearer ${token}`, userId: user._id });
});

app.post('/phones/add', async (req, res) => {
    try {
        const newPhone = new Phone(req.body);
        await newPhone.save();
        res.json({ success: true, message: "Phone added successfully!" });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error adding phone." });
    }
});

app.get('/phones', async (req, res) => {
    try {
        const phones = await Phone.find();
        res.json(phones);
    } catch (error) {
        res.status(500).json({ success: false, message: "Error fetching phones." });
    }
});

app.delete('/phones/:id', async (req, res) => {
    try {
        await Phone.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: "Phone deleted successfully!" });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error deleting phone." });
    }
});

app.put('/phones/:id/status', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const { status } = req.body;

        if (!['found', 'searching'].includes(status)) {
            return res.status(400).json({ success: false, message: "Invalid status value." });
        }

        const phone = await Phone.findByIdAndUpdate(req.params.id, { status }, { new: true });

        if (!phone) {
            return res.status(404).json({ success: false, message: "Phone not found." });
        }

        res.json({ success: true, phone });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error updating phone status." });
    }
});

app.get('/phones/user/:userId', async (req, res) => {
    try {
        const phones = await Phone.find({ userId: req.params.userId });
        res.json(phones);
    } catch (error) {
        res.status(500).json({ success: false, message: "Error fetching user's phones." });
    }
});



// Стартовая страница
app.get('/public/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
