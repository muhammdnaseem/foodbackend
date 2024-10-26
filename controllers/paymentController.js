import Stripe from 'stripe';

const stripe = new Stripe("sk_test_51PE9CHP3pfdxJbgFpP1mpFToOgVBkHDh72zdVxgPTESlZZJYA3yaYkrPKyy5BuH76QJJmrK9txReQRbivMpHHG6j00KMDwyx1i");

// Stripe Payment Handler
const stripePayment = async (req, res) => {
    const { productItems } = req.body;

    if (!Array.isArray(productItems) || productItems.length === 0) {
        return res.status(400).json({ error: 'No products provided' });
    }

    // Ensure a minimum amount of ₩1000 for all products
    const lineItems = productItems.map((product) => {
        const { price_data, quantity } = product;
        const finalAmount = Math.max(price_data.unit_amount, 1000); // ₩1000 minimum

        return {
            price_data: {
                currency: price_data.currency || 'krw',
                product_data: price_data.product_data,
                unit_amount: finalAmount,
            },
            quantity,
        };
    });

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            success_url: `${req.headers.origin}/order?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${req.headers.origin}/cancel`,
        });

        res.status(200).json({ id: session.id });
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
};

const verifyPayment = async (req, res) => {
    const { session_id } = req.query; // Ensure the session ID is retrieved correctly

    try {
        const session = await stripe.checkout.sessions.retrieve(session_id);

        if (session.payment_status === 'paid') {
            res.status(200).json({ success: true, session });
        } else {
            res.status(200).json({ success: false, message: 'Payment not successful' });
        }
    } catch (error) {
        console.error('Error verifying payment:', error.message);
        res.status(400).json({ success: false, error: error.message });
    }
};

export { stripePayment, verifyPayment };
