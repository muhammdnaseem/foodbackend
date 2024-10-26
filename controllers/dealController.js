import fs from 'fs'
import dealModel from '../models/dealModel.js'
import foodModel from '../models/foodModel.js'

//add food item

const addDeal = async (req,res) =>{

   

    const deal = new dealModel({
        dealtitle: req.body.dealtitle,
        dealdescription:req.body.dealdescription,
        dealproduct:req.body.dealproduct,
        offpercentage:req.body.offpercentage,
        dealtime: req.body.dealtime,
    })

    try {
        await deal.save();
        res.json({success:true,message:'Deal Of the day Added'})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:error})
    }
}

// All deals list

const listDeal = async (req, res) => {
    try {
      const deals = await dealModel.find({})
        .populate({
          path: 'dealproduct', 
          select: 'name image sizes', 
        });
  
      // Extract the price from the populated 'sizes' array
      const formattedDeals = deals.map(deal => {
        const product = deal.dealproduct;
        const dealprice = product?.sizes?.[0]?.price || 'N/A'; // Get the first size's price, handle undefined

        return {
          ...deal._doc, // Keep other deal properties intact
          productName: product?.name,
          productImage: product?.image,
          productPrice: dealprice,
        };
      });
  
      res.json({ success: true, data: formattedDeals });
    } catch (error) {
      console.log(error);
      res.json({ success: false, message: 'Error' });
    }
  };
  

// remove deal iDeal
const removeDeal = async (req,res)=>{
    try {
        const deal = await dealModel.findById(req.body.id);
        

        await dealModel.findByIdAndDelete(req.body.id)
        res.json({success:true,message:'Deal Removed'})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:'Error'})
    }
}

export {addDeal, listDeal, removeDeal}