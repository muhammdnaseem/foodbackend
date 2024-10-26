import userModel from './../models/userModel.js';

const addToCart = async (req, res) => {
    try {
        const { userId, itemId, selectedSize } = req.body;
        let userData = await userModel.findById(userId);

        if (!userData) {
            console.error(`User with ID ${userId} not found.`);
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        let cartData = userData.cartData || { items: {}, selectedSizes: {} };

        if (!itemId || !selectedSize) {
            console.error('Invalid itemId or selectedSize:', { itemId, selectedSize });
            return res.status(400).json({ success: false, message: 'Invalid itemId or selectedSize' });
        }


        cartData.selectedSizes[itemId] = selectedSize;


        cartData.items = cartData.items || {};

  
        const sizeId = selectedSize.id || selectedSize.name || selectedSize; 
        const itemKey = `${itemId}-${sizeId}`;


        if (!cartData.items[itemKey]) {
            cartData.items[itemKey] = 1; 
        } else {
            cartData.items[itemKey] += 1; 
        }

    
        await userModel.findByIdAndUpdate(userId, { cartData }, { new: true });

        res.json({ success: true, message: 'Added to cart' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ success: false, message: 'Error adding to cart' });
    }
};







const removeFromCart = async (req, res) => {
    try {
        const { userId, itemId } = req.body;
        
        let userData = await userModel.findById(userId);
        
        if (!userData) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        let cartData = userData.cartData || { items: {}, selectedSizes: {} };

        // Build the key for the cart item
        const itemKey = `${itemId}-${cartData.selectedSizes[itemId]}`;

        // Check if the item exists in the cart
        if (cartData.items[itemKey]) {
            cartData.items[itemKey] -= 1;

            // If quantity is zero or less, remove the item from the cart
            if (cartData.items[itemKey] <= 0) {
                delete cartData.items[itemKey];
                delete cartData.selectedSizes[itemId];
            }
        } else {
            return res.status(400).json({ success: false, message: 'Item not found in cart' });
        }

        await userModel.findByIdAndUpdate(userId, { cartData }, { new: true });

        res.json({ success: true, message: 'Removed from cart' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ success: false, message: 'Error removing from cart' });
    }
};

// update items to user cart
// update items in user cart when size is changed
const updateCart = async (req, res) => {
    try {
        const { userId, itemId, oldSize, newSize } = req.body;

        // Fetch the user's data
        let userData = await userModel.findById(userId);
        let cartData = userData.cartData;

        // Build keys for the old and new sizes
        const oldItemKey = `${itemId}-${oldSize}`;
        const newItemKey = `${itemId}-${newSize}`;

        // If the old size exists, move the quantity to the new size
        if (cartData[oldItemKey]) {
            const quantity = cartData[oldItemKey];

            // Remove the old size from the cart
            delete cartData[oldItemKey];

            // Add the quantity to the new size
            cartData[newItemKey] = (cartData[newItemKey] || 0) + quantity;
        }

        // Update the user's cart in the database
        await userModel.findByIdAndUpdate(userId, { cartData });
        
        res.json({ success: true, message: 'Cart updated successfully' });
    } catch (error) {
        console.error("Error updating cart:", error);
        res.json({ success: false, message: 'Error updating cart' });
    }
};



// fetch user cart data
const getCart = async (req, res) => {
    try {
        const userData = await userModel.findById(req.body.userId);
        const cartData = userData.cartData;

        // Initialize transformed cart items
        const transformedItems = {};
        const transformedSizes = {};

        // Process items
        for (const itemKey in cartData.items) {
            const quantity = cartData.items[itemKey];
            const [itemId, sizeKey] = itemKey.split('-'); // Split itemKey into itemId and sizeKey

            transformedItems[itemId] = transformedItems[itemId] || 0; // Initialize quantity if not present
            transformedItems[itemId] += quantity; // Aggregate quantities
        }

        // Process selected sizes
        for (const sizeKey in cartData.selectedSizes) {
            const selectedSize = cartData.selectedSizes[sizeKey];
            if (typeof selectedSize === 'object') {
                // Extract price and size if it's an object
                transformedSizes[sizeKey] = {
                    size: selectedSize.size,
                    price: selectedSize.price,
                };
            } else {
                // Handle cases where it's a direct value (like a size string)
                transformedSizes[sizeKey] = selectedSize;
            }
        }

        // Structure the final cart data
        const finalCartData = {
            items: transformedItems,
            selectedSizes: transformedSizes,
        };

        
        res.json({ success: true, cartData: finalCartData });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: 'Error' });
    }
};



export {addToCart, removeFromCart, getCart, updateCart}
