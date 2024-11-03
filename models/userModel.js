import mongoose from "mongoose";

// Define the user schema
const userSchema = new mongoose.Schema({
    name: { type: String, },
    email: { type: String, required: true, unique: true },
    mobile: { type: String },
    password: { type: String },
    googleId: { type: String,  unique: true }, 
    facebookId: { type: String, unique: true },
    cartData: {
        items: [{
            itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'food', required: true }, 
            price: {type: Number, required: true}, 
            itemQuantity: {type: Number, required: true},
            selectedSize: { type: String, required: true },  
            extraItem: { type: mongoose.Schema.Types.ObjectId, ref: 'food' }, 
            spicyLevel: { type: String },  
            addOnItem: { type: mongoose.Schema.Types.ObjectId, ref: 'food' },
            drinkItem: { type: mongoose.Schema.Types.ObjectId, ref: 'food' }
        }],
    },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    verificationTokenExpiresAt: Date,
    resetPasswordToken: String,
    resetPasswordExpiresAt: Date,
}, { minimize: false });

// Pre-save middleware to enforce password requirement conditionally
// userSchema.pre('save', function (next) {
//     if (!this.googleId && !this.password) {
//         return next(new Error('Password is required for non-OAuth users.'));
//     }
//     next();
// });

// Export the model safely (only register if not already registered)
const userModel = mongoose.models.user || mongoose.model('user', userSchema);

export default userModel;
