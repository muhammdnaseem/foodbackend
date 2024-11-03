import express from 'express';
import axios from 'axios';
import userModel from "../models/userModel.js";
import jwt from 'jsonwebtoken';
import {
    loginUser,
    registerUser,
    authGoogle,
    googleCallback,
    authFacebook, 
    facebookCallback,
    sendDirectVerificationEmail,
    userDetails,
    userUpdate,
    forgotPassword,
    resetPassword,
    VerifyToken
} from '../controllers/userController.js';
import authMiddleware from './../middleware/auth.js';
import passport from 'passport';

const userRouter = express.Router();

// Register and Login routes
userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.post('/verify-token', VerifyToken);



const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = `https://foodbackend-production-a94c.up.railway.app/api/user/auth/google/callback`;

// Initiates the Google Login flow
userRouter.get('/auth/google', (req, res) => {
  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=profile email`;
  res.redirect(url);
});
userRouter.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;

  try {
    // Exchange authorization code for access token
    const { data } = await axios.post('https://oauth2.googleapis.com/token', {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code',
    });

    const { access_token } = data;

    // Use access_token to fetch user profile
    const { data: profile } = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    // Check if the user already exists in the database
    let existingUser = await userModel.findOne({ googleId: profile.id });

    if (!existingUser) {
      // Create a new user
      existingUser = new userModel({
        googleId: profile.id,
        email: profile.email,
        name: profile.name,
        picture: profile.picture,
      });
      await existingUser.save();
    }

    // Generate a JWT token
    
    // Generate a JWT token
    const token = jwt.sign({ id: existingUser._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    // Redirect to the frontend with the token
    const frontendUrl = `${process.env.FRONTEND_URL}/auth/google/callback?token=${token}`;
    res.redirect(frontendUrl);
  } catch (error) {
    const errorMessage = error.response && error.response.data ? error.response.data.error : error.message;
    console.error('Error:', errorMessage);
    res.redirect('/login');
  }
});


const APP_ID = process.env.FACEBOOK_APP_ID;
const APP_SECRET = process.env.FACEBOOK_APP_SECRET;
const REDIRECT_URIF = 'https://foodbackend-production-a94c.up.railway.app/api/user/auth/facebook/callback';

// Initiates the Facebook Login flow
userRouter.get('/auth/facebook', (req, res) => {
  const url = `https://www.facebook.com/v13.0/dialog/oauth?client_id=${APP_ID}&redirect_uri=${REDIRECT_URIF}&scope=email`;
  res.redirect(url);
});

// Callback URL for handling the Facebook Login response
userRouter.get('/auth/facebook/callback', async (req, res) => {
  const { code } = req.query;

  try {
    // Exchange authorization code for access token
    const { data } = await axios.get(`https://graph.facebook.com/v13.0/oauth/access_token?client_id=${APP_ID}&client_secret=${APP_SECRET}&code=${code}&redirect_uri=${REDIRECT_URIF}`);

    const { access_token } = data;

    // Use access_token to fetch user profile
    const { data: profile } = await axios.get(`https://graph.facebook.com/v13.0/me?fields=id,name,email,picture&access_token=${access_token}`);

    // Check if the user already exists in the database
    let existingUser = await userModel.findOne({ facebookId: profile.id });

    if (!existingUser) {
      // Create a new user
      existingUser = new userModel({
        facebookId: profile.id, // Store Facebook ID
        email: profile.email,
        name: profile.name,
        picture: profile.picture.data.url, // Make sure to get the correct URL from the profile data
      });
      await existingUser.save();
    }

    // Generate a JWT token
    const token = jwt.sign({ id: existingUser._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    // Redirect to the frontend with the token
    const frontendUrl = `${process.env.FRONTEND_URL}/auth/google/callback?token=${token}`;
    res.redirect(frontendUrl);
  } catch (error) {
    console.error('Error:', error.response ? error.response.data.error : error.message);
    res.redirect('/login');
  }
});


userRouter.post('/sendEmail', sendDirectVerificationEmail);




// Forgot and Reset Password
userRouter.post('/forgotpassword', forgotPassword);
userRouter.post('/resetpassword', resetPassword);

// User details and profile update
userRouter.get('/details', authMiddleware, userDetails); // Changed to GET for user details retrieval
userRouter.patch('/update', userUpdate);

export default userRouter;
