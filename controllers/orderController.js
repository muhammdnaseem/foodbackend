import orderModel from './../models/orderModel.js';
import userModel from './../models/userModel.js';
import Stripe from "stripe"

const stripe =  new Stripe(process.env.STRIPE_SECRET_KEY)
const placeOrder = async (req, res) => {
    console.log("Request Body:", req.body); // Log the entire request body
    const frontend_url = process.env.FRONTEND_URL;

    try {
        // Check if items exist
        if (!req.body.items || !Array.isArray(req.body.items)) {
            console.error("Items validation failed:", req.body.items); // Log items validation failure
            return res.status(400).json({ success: false, message: "Items are required and must be an array." });
        }

        // Validate item structure
        for (const item of req.body.items) {
            if (!item.itemId || !item.name || !item.quantity) {
                console.error("Item validation failed:", item); // Log item validation failure
                return res.status(400).json({ 
                    success: false, 
                    message: "Each item must have an itemId, name, and quantity." 
                });
            }
        }

        // Create a new order
        const newOrder = new orderModel({
            userId: req.body.userId,
            items: req.body.items.map(item => ({
                itemId: item.itemId,
                name: item.name,
                description: item.description || '', // Optional field
                price: item.price || 0, // Optional field, default to 0 if not provided
                quantity: item.quantity,
                size: item.size || 'N/A' // Optional field, default to 'N/A' if not provided
            })),
            amount: req.body.amount,
            address: req.body.address,
        });

        console.log('New Order:', newOrder); // Log the new order being saved

        // Save the order to the database
        const savedOrder = await newOrder.save();
        console.log('Order saved:', savedOrder); // Log the saved order

        // Clear the user's cartData after placing the order
        await userModel.findByIdAndUpdate(req.body.userId, {
            cartData: {
                items: {},
                selectedSizes: {}
            }
        });

        // Create payment session
        const productItems = req.body.items.map(item => ({
            price_data: {
                currency: 'krw',
                product_data: {
                    name: item.name,
                    description: item.description || '',
                },
                unit_amount: item.price ? Math.max(item.price * 100, 1000) : 1000, // Ensure price is at least ₩1000 or default
            },
            quantity: item.quantity,
        }));

        console.log('Product Items for Stripe:', productItems); // Log the product items for Stripe

        // Create the Stripe session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card', 'samsung_pay'],
            line_items: productItems,
            mode: 'payment',
            success_url: `${frontend_url}/success?orderId=${savedOrder._id}&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${frontend_url}/order-cancelled`,
        });

        console.log('Stripe Session:', session); // Log the Stripe session

        // Save the Stripe session ID to the order
        await orderModel.findByIdAndUpdate(savedOrder._id, { stripeSessionId: session.id });

        // Respond with the session ID to the frontend
        res.json({ success: true, sessionId: session.id });
    } catch (error) {
        console.error('Error in placeOrder:', error.message);
        res.status(500).json({ success: false, message: "Error occurred while placing the order.", error: error.message });
    }
};



// Verify payment function
const verifyPayment = async (req, res) => {
    const { orderId, sessionId } = req.query;
    console.log('Received request to verify payment for order ID:', orderId, 'and session ID:', sessionId);

    if (!orderId || !sessionId) {
        console.log('Order ID or Session ID is missing in the request');
        return res.status(400).json({ success: false, message: 'Order ID and Session ID are required' });
    }

    try {
        // Retrieve the order by its ID
        console.log('Attempting to find the order in the database');
        const order = await orderModel.findById(orderId);

        if (!order) {
            console.log('Order not found in the database');
            return res.status(404).json({ success: false, message: 'Order not found' });
        }

        console.log('Order found:', order);

        // Check if the payment is already verified
        if (order.payment) {
            console.log('Payment for this order is already verified');
            return res.json({ success: true, message: 'Payment already verified' });
        }

        // Check if the order has a valid Stripe session ID
        console.log(order.stripeSessionId);
        console.log(sessionId);
        if (order.stripeSessionId !== sessionId) {
            console.log('Provided session ID does not match the stored session ID for this order');
            return res.status(400).json({ success: false, message: 'Invalid session ID' });
        }

        console.log('Stripe session ID matches:', order.stripeSessionId);

        // Retrieve the Stripe session using the session ID
        console.log('Retrieving the Stripe session');
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        console.log('Stripe session retrieved:', session);

        // Verify if the payment was successful
        if (session.payment_status === 'paid') {
            console.log('Payment status is "paid". Updating payment status in the database.');
            // Update the payment status in the database
            await orderModel.findByIdAndUpdate(orderId, { payment: true });

            console.log('Payment status updated successfully in the database');
            res.json({ success: true, message: 'Payment successful', session });
        } else {
            console.log('Payment status is not "paid". Payment not successful');
            res.status(400).json({ success: false, message: 'Payment not successful' });
        }
    } catch (error) {
        console.error('Error verifying payment:', error.message);
        res.status(500).json({ success: false, message: 'An error occurred while verifying the payment', error: error.message });
    }
};



const verifyOrder = async (req, res) => {
    const { orderId, success } = req.body;
    try {
        if (success === true) { // Make sure you're checking for boolean
            await orderModel.findByIdAndUpdate(orderId, { payment: true });
            res.json({ success: true, message: "Paid" });
        } else {
            await orderModel.findByIdAndDelete(orderId);
            res.json({ success: false, message: "Not Paid" });
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ success: false, message: "Error occurred while verifying the order." });
    }
};











// user orders for frontend
const userOrders = async (req,res) => {
    try {
        const orders = await orderModel.find({userId:req.body.userId})
        res.json({success:true, data:orders})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:"Error"})
    }
}

// listing orders for admin panel
const listOrders = async (req,res) =>{
   try {
    const orders = await orderModel.find({});
    res.json({success:true, data:orders})
   } catch (error) {
        console.log(error)
        res.json({success:false, message:"Error"})  
   } 
}

// api for updating order status
const updateStatus = async (req, res) =>{
    try {
        await orderModel.findByIdAndUpdate(req.body.orderId,{status:req.body.status})
        res.json({success:true, message:"Status Updated"})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:"Error"})  
    }
}

export {placeOrder, verifyOrder, userOrders, listOrders, updateStatus, verifyPayment}