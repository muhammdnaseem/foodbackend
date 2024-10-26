import fs from 'fs'
import foodModel from '../models/foodModel.js'
import mongoose from 'mongoose';
//add food item

const addFood = async (req, res) => {
    let image_filename = `${req.file.filename}`;

    // Parse sizes from the request body
    let sizes = [];
    if (req.body.sizes) {
        try {
            sizes = JSON.parse(req.body.sizes);
        } catch (error) {
            return res.status(400).json({ success: false, message: 'Invalid sizes format' });
        }
    }

    // Validate category
    if (!mongoose.Types.ObjectId.isValid(req.body.category)) {
        return res.status(400).json({ success: false, message: 'Invalid category ID' });
    }

    const food = new foodModel({
        name: req.body.name,
        description: req.body.description,
        sizes: sizes.length > 0 ? sizes : [{ size: 'Regular', price: req.body.price }],
        category: req.body.category,
        image: image_filename
    });

    try {
        await food.save();
        res.json({ success: true, message: 'Food item added successfully' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ success: false, message: 'Error adding food item' });
    }
};


// All food list

const listFood = async (req,res) =>{
    try {
        const foods = await foodModel.find({});
        res.json({success:true,data:foods})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:'Error'})
    }
}

// remove food item

const removeFood = async (req,res)=>{
    try {
        const food = await foodModel.findById(req.body.id);
        fs.unlink(`uploads/${food.image}`,()=>{})

        await foodModel.findByIdAndDelete(req.body.id)
        res.json({success:true,message:'Food Removed'})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:'Error'})
    }
}

const addReview = async (req, res) => {
    const { product, rating, comment } = req.body;

    // Extract foodId from the product array
    const foodId = Array.isArray(product) && product.length > 0 ? product[0] : null;

    // Validate inputs
    if (!foodId || !mongoose.Types.ObjectId.isValid(foodId)) {
        console.log(foodId);
        return res.status(400).json({ success: false, message: 'Invalid food ID' });
    }
    if (rating === undefined || comment === undefined) {
        return res.status(400).json({ success: false, message: 'Rating and comment are required' });
    }

    try {
        const food = await foodModel.findById(foodId);
        if (!food) {
            return res.status(404).json({ success: false, message: 'Food item not found' });
        }

        // Add the review to the food item's reviews array
        food.reviews.push({ rating, comment });
        
        // Calculate the average rating
        const totalRatings = food.reviews.reduce((acc, review) => acc + review.rating, 0);
        food.averageRating = totalRatings / food.reviews.length;

        await food.save();

        res.json({ success: true, message: 'Review added successfully', data: food });
    } catch (error) {
        console.log(error);
        res.status(500).json({ success: false, message: 'Error adding review' });
    }
};




export {addFood, listFood, removeFood, addReview}