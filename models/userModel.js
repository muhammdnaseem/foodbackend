import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: { type: String },
    email: { type: String, required: true, unique: true },
    mobile: { type: String },
    password: { type: String },
    googleId: { type: String, sparse: true }, // Google ID can be null but will not conflict due to sparse index
    facebookId: { type: String, sparse: true }, // Facebook ID can also be null
    cartData: {
        items: [{
            itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'food' },
            selectedSize: { type: String },
            itemQuantity: { type: Number },
            price: { type: Number },
            extraItem: { type: mongoose.Schema.Types.ObjectId, ref: 'food' },
            spicyLevel: { type: String },
            addOnItem: { type: mongoose.Schema.Types.ObjectId, ref: 'food' },
            drinkItem: { type: mongoose.Schema.Types.ObjectId, ref: 'food' },
            specialInstructions: { type: String },
        }],
    },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    verificationTokenExpiresAt: Date,
    resetPasswordToken: String,
    resetPasswordExpiresAt: Date,
}, { minimize: false });

// Apply sparse index directly in schema
userSchema.index({ googleId: 1 }, { unique: true, sparse: true });
userSchema.index({ facebookId: 1 }, { unique: true, sparse: true });

// Export the model safely
const userModel = mongoose.models.user || mongoose.model('user', userSchema);

export default userModel;
