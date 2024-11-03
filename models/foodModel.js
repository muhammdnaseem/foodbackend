import mongoose from "mongoose";

const foodSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    sizes: [{
        size: { type: String, required: true },
        sizedescription: {type: String, required: true},
        price: { type: Number, required: true },
    }],
    image: { type: String, required: true },
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'category',
        required: true
    },
    reviews: [{ 
      rating: { type: Number, required: true }, 
      comment: { type: String, required: true } 
  }]
});

const foodModel = mongoose.models.food || mongoose.model("food", foodSchema);

export default foodModel;
