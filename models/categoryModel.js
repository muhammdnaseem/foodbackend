import mongoose from "mongoose";

const categorySchema = new mongoose.Schema({
    categoryname: {type: String,required: true},
    categorydetails: {type: String,required: true},
    categoryimage: {type: String,required: true},
})

const categoryModel = mongoose.model.category || mongoose.model("category",categorySchema);

export default categoryModel;