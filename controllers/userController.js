import userModel from "../models/userModel.js";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import validator from 'validator';
import nodemailer from 'nodemailer';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import FacebookStrategy from 'passport-facebook';
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
    const { name, password, email, otp } = req.body;

    try {

        // Find the user by email
        const user = await userModel.findOne({ email });
        if (!validator.isEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email' });
        // if (password.length < ) return res.status(400).json({ success: false, message: 'Password too short' });

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
   
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Check if the OTP is correct and has not expired
        if (user.verificationToken !== otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }

        // Check if the verification token has expired
        if (user.verificationTokenExpiresAt < Date.now()) {
            return res.status(400).json({ success: false, message: 'OTP has expired' });
        }
        
       

user.name = name;
user.password = hashedPassword;
user.isVerified = true;
user.verificationToken = null; 
user.verificationTokenExpiresAt = null; 

// Save the updated user
await user.save();


        
        const token = createToken(user._id);
        res.status(201).json({ success: true, message: 'Registration successful. Please verify your email.', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error registering user' });
    }
};


// Function to handle email verification with a new user model instance
const sendDirectVerificationEmail = async (req, res) => {
    const { email } = req.body;

    // Check if the user already exists
    if (await userModel.findOne({ email })) {
        return res.status(409).json({ success: false, message: 'User already exists' });
    }

    // Validate email presence
    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
    const verificationToken = generateOTP();

    // Create new user without googleId field if it's not applicable
    const newUser = new userModel({
        email,
        verificationToken,
        verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000,
    });

    try {
        await newUser.save();
        const isPasswordReset = "false";
        await sendVerificationEmail(email, verificationToken, isPasswordReset);
        res.status(200).json({ success: true, message: 'Verification email sent.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error sending verification email', error });
    }
};




// Function to send franchise email
const sendFranchiseEmail = async (req, res) => {
    const { name, email, message } = req.body;

    try {
        await sendEmail(name, email, message);
        res.status(200).json({ success: true, message: 'Franchise email sent successfully.' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ success: false, message: 'Error sending email', error });
    }
};

// Helper function to send the email
const sendEmail = async (name, email, message) => {
    const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // Use TLS
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: `"Henn Bun" <${process.env.EMAIL_USER}>`,
        to: 'saidj4671@gmail.com',
        subject: `Franchise Inquiry from ${name}`,
        text: `You received a new message:\n\nName: ${name}\nEmail: ${email}\nMessage: ${message}`,
        html: `
            <p>You received a new franchise inquiry:</p>
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Message:</strong> ${message}</p>
        `,
    };

    await transporter.sendMail(mailOptions);
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

       
        
        await sendResetVerificationEmail(email, resetToken);

        res.status(200).json({ success: true, message: 'Reset link sent to your email!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error processing request' });
    }
};



// Send verification email
const sendVerificationEmail = async (email, verificationToken) => {
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

        
            // For OTP verification, send just the OTP in text
            subject = 'Email Verification - OTP';
            text = `Your OTP for email verification is: ${verificationToken}`;
            html = `<p> <strong>${verificationToken}</strong></p>`;
      

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



const sendResetVerificationEmail = async (email, verificationToken) => {
    const verificationUrl = `${process.env.FRONTEND_URL}/reset-password?resettoken=${verificationToken}`;
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

        
            // For password reset, send the link
            subject = 'Password Reset';
            text = `Please reset your password by clicking the following link: ${verificationUrl}`;
            html = `<p> <a href="${verificationUrl}">${verificationUrl}</a></p>`;
       
          

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



const VerifyToken = async (req, res) => {
    const { resettoken } = req.body;
   

    try {
      

        const user = await userModel.findOne({
            resetPasswordToken: resettoken,
        });
        
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid token' });
        }
        
        if (user.resetPasswordExpiresAt <= Date.now()) {
            return res.status(400).json({ success: false, message: 'Token has expired' });
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

    console.log('new', newPassword, userId)

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
        // If a password is provided, hash it and include it in the update
        if (password) {
            const bcrypt = require('bcryptjs');
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            updatedData.password = hashedPassword;
        }

        // Update user data
        const user = await userModel.findByIdAndUpdate(userId, updatedData, { new: true });

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.status(200).json({ success: true, message: 'User Data Updated' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ success: false, message: 'Error updating user' });
    }
};


// Update user password
const updatePassword = async (req, res) => {
    const { userId, currentpassword, newPassword } = req.body; // Destructure password details from request body

    try {
        // Validate required fields
        //console.log('ppp', currentpassword, newPassword);
        if (!currentpassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'Current password and new password are required' });
        }

        // Retrieve the user by ID
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Compare the provided current password with the stored hashed password
        const isMatch = await bcrypt.compare(currentpassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error updating password' });
    }
};



passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
  },
  async (accessToken, refreshToken, profile, cb) => {
    try {
      console.log("Google authentication callback triggered"); // Check if callback was hit
      
      // Check if user already exists
      let user = await userModel.findOne({ email: profile.emails[0].value });
      console.log("User lookup completed:", user); // Logs user data if found, otherwise null

      if (!user) {
        console.log("User not found, creating a new user"); // Check if user creation is needed
        
        // Create a new user if not found
        user = new userModel({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.emails[0].value,
          isVerified: true,
        });
        
        await user.save();
        console.log("New user saved successfully:", user); // Logs the new user data
      }

      // If user exists or newly created, create a token
      const token = createToken(user._id);
      console.log("JWT token created:", token); // Log the generated token

      // Return the user and token directly to stop redirection for debugging
      //cb(null, { user, token });
    } catch (err) {
      console.error("Error during Google authentication:", err); // Log any errors that occur
      cb(err, null); // Pass error to cb function as expected
    }
  }
));



// Facebook authentication strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,  // Your Facebook App ID
    clientSecret: process.env.FACEBOOK_APP_SECRET,  // Your Facebook App Secret
    callbackURL: `https://foodbackend-production-a94c.up.railway.app/api/user/auth/facebook/callback`, // Your callback URL
    profileFields: ['id', 'emails', 'name']  // Fields to retrieve from Facebook
  },
  async (accessToken, refreshToken, profile, cb) => {
    try {
      // Check if the user already exists by email
      let user = await userModel.findOne({ email: profile.emails[0].value });

      if (!user) {
        // Create a new user if not found
        user = new userModel({
          facebookId: profile.id,
          name: profile.displayName,
          email: profile.emails[0].value,
          isVerified: true,
        });

        await user.save(); 
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' } // Set token expiration time
      );

      return cb(null, { user, token });
    } catch (err) {
      return cb(err, null);
    }
  }
));



// Serialize user to session
passport.serializeUser((user, done) => {
    done(null, user);
  });
  
  // Deserialize user from session
  passport.deserializeUser((user, done) => {
    done(null, user);
  });


// Google authentication routes
const authGoogle = passport.authenticate('google', { scope: ['profile', 'email'] });

const googleCallback = passport.authenticate('google', {
    failureRedirect: '/login',
    successRedirect: '/',
});

// Facebook authentication routes
const authFacebook = passport.authenticate('facebook', { scope: ['email'] });
const facebookCallback = passport.authenticate('facebook', {
    failureRedirect: '/login',
    successRedirect: '/',
});

export {
    loginUser,
    registerUser,
    sendDirectVerificationEmail,
    forgotPassword,
    resetPassword,
    VerifyToken,
    userDetails,
    userUpdate,
    authGoogle,
    googleCallback,
    authFacebook,
    facebookCallback,
    updatePassword,
    sendFranchiseEmail
};
