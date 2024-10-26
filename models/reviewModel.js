import mongoose from "mongoose";

const reviewSchema = new mongoose.Schema({
    rating: { type: Number, required: true },
    comment: { type: String, required: true },
    product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'order',
        required: true
    },
});

const reviewModel = mongoose.models.review || mongoose.model("review", reviewSchema);

export default reviewModel;
