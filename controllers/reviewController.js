import fs from 'fs'
import reviewModel from '../models/reviewModel.js'

//add food item

const addReview = async (req,res) =>{

   

    const review = new reviewModel({
        rating: req.body.rating,
        comment:req.body.comment,
        product:req.body.product,
    })

    try {
        await review.save();
        res.json({success:true,message:'review Added'})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:'Error'})
    }
}

// All review list

const listReview = async (req,res) =>{
    try {
        const categories = await reviewModel.find({});
        res.json({success:true,data:categories})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:'Error'})
    }
}

// remove review ireview
const removeReview = async (req,res)=>{
    try {
        const review = await reviewModel.findById(req.body.id);
        

        await reviewModel.findByIdAndDelete(req.body.id)
        res.json({success:true,message:'review Removed'})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:'Error'})
    }
}

export {addReview, listReview, removeReview}