import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
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
const port = process.env.PORT || 4000;  // Define the port properly

// Middleware
app.use(express.json());
app.use(cors());

// DB Connection
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log('NOT CONNECTED TO NETWORK', err));

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

app.get('/', (req, res) => {
  res.send('API working');
});

app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});
