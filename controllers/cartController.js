import userModel from './../models/userModel.js';

const addToCart = async (req, res) => {
    try {
        const { userId, newItem } = req.body; // Get userId and newItem from the request body


        // Validate userId
        if (!userId) {
            return res.status(400).json({ success: false, message: 'Invalid userId' });
        }

        // Find the user
        let userData = await userModel.findById(userId);
        if (!userData) {
            console.error(`User with ID ${userId} not found.`);
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Initialize cartData if not present
        let cartData = userData.cartData || { items: [] };
       

        // Retrieve new item details from newItem object
        const { 
            itemId, 
            selectedSize,
            itemQuantity, 
            price, 
            extraItem, 
            spicyLevel, 
            addOnItem, 
            drinkItem, 
            specialInstructions, 
        } = newItem || {};

        // Validate itemId and selectedSize
        if (!itemId || !selectedSize) {
            return res.status(400).json({
                success: false,
                message: `Invalid ${!itemId ? 'itemId' : 'selectedSize'}`
            });
        }

      
        // Check if an existing item with the same itemId and selectedSize already exists
const existingItemIndex = cartData.items.findIndex(
    (item) => item.itemId && item.itemId.toString() === itemId.toString() && item.selectedSize === selectedSize
);

      

        if (existingItemIndex !== -1) {
            // If item exists, update only the quantity
            //console.log('cart data are ', itemId, itemQuantity);
            await userModel.updateOne(
                { _id: userId }, // Match the user
                {
                    $set: { "cartData.items.$[item].itemQuantity": itemQuantity },
                },
                {
                    arrayFilters: [
                        { 
                            "item.itemId": itemId, 
                            "item.selectedSize": selectedSize 
                        },
                    ],
                }
            );
            
         
            //console.log('cart data are ', cartData);
            return res.json({ success: true, message: 'Quantity updated' });
           
        } else {
            // If item doesn't exist, create a new entry
            const newItemEntry = {
                itemId,
                selectedSize,
                itemQuantity,
                price,
                extraItem,
                spicyLevel,
                addOnItem,
                drinkItem,
                specialInstructions,
            };
            cartData.items.push(newItemEntry); // Add the new item to the cart
            
            // Update user's cart data in the database
            await userModel.findByIdAndUpdate(userId, { cartData }, { new: true });
            console.log("new item");
            return res.json({ success: true, message: 'Added to cart' });
        }
    } catch (error) {
        console.error('Error adding to cart:', error);
        res.status(500).json({ success: false, message: 'Error adding to cart' });
    }
};




const removeFromCart = async (req, res) => {
    try {
        const { userId, itemId, selectedSize } = req.body;

        let userData = await userModel.findById(userId);
        
        if (!userData) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        let cartData = userData.cartData || { items: {}, selectedSizes: {} };

        // Debug: Check the current state of cartData
        console.log("Current cart data:", cartData);

        // Ensure selectedSize exists for the itemId
        if (!cartData.selectedSizes[itemId]) {
            return res.status(400).json({ success: false, message: 'Item size not found in cart' });
        }

        const itemKey = `${itemId}-${cartData.selectedSizes[itemId]}`;
        if (cartData.items[itemKey]) {
            cartData.items[itemKey] -= 1;

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
        console.error("Error in removeFromCart:", error);
        res.status(500).json({ success: false, message: 'Error removing from cart', error: error.message });
    }
};


// Update items in user cart when size is changed
const updateCart = async (req, res) => {
    try {
        const { userId, itemId, oldSize, newSize } = req.body;

        // Fetch the user's data
        const userData = await userModel.findById(userId);
        const cartData = userData.cartData;
        console.log("Current Cart Data:", cartData);

        // Build keys for the old and new sizes
        const oldItemKey = `${itemId}-${oldSize}`;
        const newItemKey = `${itemId}-${newSize}`;

        if (cartData.selectedSizes[oldItemKey]) {
            // Remove the old size entry and save the necessary details
            const existingItem = cartData.selectedSizes[oldItemKey];
            delete cartData.selectedSizes[oldItemKey];

            // Add the new size entry to selectedSizes
            cartData.selectedSizes[newItemKey] = {
                size: newSize,
                price: existingItem.price, // Maintain the same price, or update as needed
                _id: existingItem._id // Keep the same ID if applicable
            };

            // Update or add the quantity in items for newItemKey
            cartData.items[newItemKey] = (cartData.items[oldItemKey] || 1); 
            delete cartData.items[oldItemKey]; // Remove old size entry from items
            console.log(`Updated Cart: Moved from ${oldItemKey} to ${newItemKey}`);
        } else {
            console.log(`Old item key ${oldItemKey} does not exist in selectedSizes`);
        }

        // Update the user's cart in the database
        await userModel.findByIdAndUpdate(userId, { cartData });
        res.json({ success: true, message: 'Cart updated successfully', updatedCart: cartData });
    } catch (error) {
        console.error("Error updating cart:", error);
        res.json({ success: false, message: 'Error updating cart' });
    }
};

const deleteItemFromCart = async (req, res) => {
    try {
        const { userId, itemId, selectedSize } = req.body;

        console.log('kkk', itemId, selectedSize, userId);

        if (!userId || !itemId || !selectedSize) {
            return res.status(400).json({ success: false, message: 'Invalid userId, itemId, or selectedSize' });
        }

        const userData = await userModel.findById(userId);
        if (!userData) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        let cartItems = userData.cartData?.items || [];
        console.log('cart data', cartItems);

        // Find the index of the item to delete
        const itemIndex = cartItems.findIndex(
            (item) =>
                item.itemId.toString() === itemId && // Compare itemId
                item.selectedSize.toLowerCase() === selectedSize.toLowerCase() // Case-insensitive comparison for selectedSize
        );

        if (itemIndex === -1) {
            return res.status(400).json({ success: false, message: 'Item not found in cart' });
        }

        // Remove the item from the array
        cartItems.splice(itemIndex, 1);

        // Update the user's cart data
        userData.cartData.items = cartItems;
        await userData.save();

        res.json({ success: true, message: 'Item deleted from cart' });
    } catch (error) {
        console.error('Error deleting item from cart:', error);
        res.status(500).json({ success: false, message: 'Error deleting item from cart', error: error.message });
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

        // console.log('user data ', finalCartData);

        
        res.json({ success: true, cartData: finalCartData });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: 'Error' });
    }
};






export {addToCart, removeFromCart, getCart, updateCart, deleteItemFromCart}
