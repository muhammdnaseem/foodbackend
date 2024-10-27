import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import './strategies/googleStrategy.js'; // Import the Google strategy setup
import foodRouter from './routes/foodRoute.js';
import dealRouter from './routes/dealRoute.js';
import categoryRouter from './routes/categoryRoute.js';
import paymentRouter from './routes/paymentRoute.js';
import reviewRouter from './routes/reviewRoute.js';
import userRouter from './routes/userRoute.js';
import cartRouter from './routes/cartRoute.js';
import orderRouter from './routes/orderRoute.js';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(express.json());
app.use(cors());

// Configure express-session
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key', // Secure random key for signing sessions
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60, // 1-hour session expiration
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      httpOnly: true, // Prevent client-side JS from accessing the cookie
    },
  })
);

// Initialize Passport and session management
app.use(passport.initialize());
app.use(passport.session());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('NOT CONNECTED TO NETWORK', err));

// API Endpoints
app.use('/api/food', foodRouter);
app.use('/images', express.static('uploads'));
app.use('/api/category', categoryRouter);
app.use('/categoryimages', express.static('uploads/categories'));
app.use('/api/deal', dealRouter);
app.use('/api/user', userRouter);
app.use('/api/review', reviewRouter);
app.use('/api/cart', cartRouter);
app.use('/api/order', orderRouter);
app.use('/api/payment', paymentRouter);

// Health check endpoint
app.get('/', (req, res) => {
  res.send('API working');
});

// Start the server
app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});
