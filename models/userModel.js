import mongoose from "mongoose";

// Define the user schema
const userSchema = new mongoose.Schema({
    name: { type: String, },
    email: { type: String, required: true, unique: true },
    mobile: { type: String },
    password: { type: String },
    googleId: { type: String }, 
    cartData: {
        type: Object,
        default: {
            items: {},
            selectedSizes: {},
        }
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
