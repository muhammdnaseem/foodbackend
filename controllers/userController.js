import userModel from "../models/userModel.js";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import validator from 'validator';
import nodemailer from 'nodemailer';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();


// Create JWT token
const createToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '24d' });

// Login user
// Login user
const loginUser = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: 'User does not exist' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials' });

        const token = createToken(user._id);
        res.status(200).json({ success: true, message: 'Login successful', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
};


// Register user
// Register user
const registerUser = async (req, res) => {
    const { name, password, email } = req.body;

    try {
        // Check if user already exists
        if (await userModel.findOne({ email })) {
            return res.status(409).json({ success: false, message: 'User already exists' });
        }

        // Validate email and password
        if (!validator.isEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email' });
        if (password.length < 8) return res.status(400).json({ success: false, message: 'Password too short' });

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        // Generate 6-digit OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString(); 
const verificationToken = generateOTP(); // OTP as a string

        // Create new user
        const newUser = new userModel({
            name,
            email,
            password: hashedPassword,
            verificationToken,
            verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000,
        });

        // Save user to the database
        await newUser.save();

        // Send verification email
        sendVerificationEmail(email, verificationToken).catch(error => {
            console.error('Error sending verification email:', error);
        });

        // Create JWT token and return response
        const token = createToken(newUser._id);
        res.status(201).json({ success: true, message: 'Registration successful. Please verify your email.', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error registering user' });
    }
};


// Send verification email
const sendVerificationEmail = async (email, verificationToken, isPasswordReset = false) => {
    const verificationUrl = `https://hennbun.ca/aboutus?resettoken=${verificationToken}`;
    try {
        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD,
            },
        });

        let subject, text, html;

        if (isPasswordReset) {
            // For password reset, send the link
            subject = 'Password Reset';
            text = `Please reset your password by clicking the following link: ${verificationUrl}`;
            html = `<p> <a href="${verificationUrl}">${verificationUrl}</a></p>`;
        } else {
            // For OTP verification, send just the OTP in text
            subject = 'Email Verification - OTP';
            text = `Your OTP for email verification is: ${verificationToken}`;
            html = `<p> <strong>${verificationToken}</strong></p>`;
        }

        const mailOptions = {
            from: `"Henn Bun" <${process.env.EMAIL_USER}>`,
            to: email,
            subject,
            text,
            html,
        };

        await transporter.sendMail(mailOptions);
        console.log('Verification email sent successfully');
    } catch (error) {
        console.error('Error sending verification email:', error);
    }
};

// Forgot password
const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpiresAt = Date.now() + 3600000; // 1 hour

        await user.save();

        const resetUrl = `http://localhost:5173/resetpassword?token=${resetToken}`;
        await sendVerificationEmail(email, resetToken, true);

        res.status(200).json({ success: true, message: 'Reset link sent to your email!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error processing request' });
    }
};


const VerifyToken = async (req, res) => {
    const { resettoken } = req.body;

    try {
        const user = await userModel.findOne({
            resetPasswordToken: resettoken,
            resetPasswordExpiresAt: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired token' });
        }

        // Send success response with userId
        return res.status(200).json({ success: true, userId: user._id });
    } catch (error) {
        console.error('Error verifying token:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};



// Reset password
const resetPassword = async (req, res) => {
    const { userId, newPassword } = req.body;

    try {
        // Find the user by ID
        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(400).json({ success: false, message: 'User not found' });
        }

        // Generate salt and hash the new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);

        // Clear the reset token and expiry
        user.resetPasswordToken = undefined;
        user.resetPasswordExpiresAt = undefined;

        // Save the updated user
        await user.save();

        res.status(200).json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};



// Get user details
const userDetails = async (req, res) => {
    try {
        const user = await userModel.findById(req.body.userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        // Only send back non-sensitive data
        const { password, ...userData } = user.toObject(); // Convert mongoose doc to plain object
        res.status(200).json({ success: true, data: userData });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error fetching user details' });
    }
};



// Update user details
const userUpdate = async (req, res) => {
    const { userId, password, ...updatedData } = req.body; // Destructure password from request body

    try {
        // Check if a new password is provided
        if (password) {
            const salt = await bcrypt.genSalt(10); // Generate a salt for hashing
            updatedData.password = await bcrypt.hash(password, salt); // Hash the new password
        }

        const user = await userModel.findByIdAndUpdate(userId, updatedData, { new: true });
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        // Exclude password from the response
        const { password: _, ...userData } = user.toObject(); // Convert mongoose doc to plain object
        res.status(200).json({ success: true, data: userData }); // Return updated user data without password
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error updating user' });
    }
};


// passport.js


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `http://localhost:5173/auth/google/callback`, // Ensure callback URL matches your frontend
  },
  async (accessToken, refreshToken, profile, cb) => {
    try {
      const user = await User.findOrCreate({ googleId: profile.id });
      return cb(null, user);
    } catch (err) {
      return cb(err, null);
    }
  }
));


// Google authentication routes
const authGoogle = passport.authenticate('google', { scope: ['profile', 'email'] });

const googleCallback = passport.authenticate('google', {
    failureRedirect: '/login',
    successRedirect: '/dashboard',
});

export {
    loginUser,
    registerUser,
    sendVerificationEmail,
    forgotPassword,
    resetPassword,
    VerifyToken,
    userDetails,
    userUpdate,
    authGoogle,
    googleCallback,
};
