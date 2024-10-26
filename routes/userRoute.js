import express from 'express';
import {
    loginUser,
    registerUser,
    authGoogle,
    googleCallback,
    sendVerificationEmail,
    userDetails,
    userUpdate,
    forgotPassword,
    resetPassword
} from '../controllers/userController.js';
import authMiddleware from './../middleware/auth.js';
import passport from 'passport';

const userRouter = express.Router();

// Register and Login routes
userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);

// Google authentication routes
userRouter.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] })); // Request profile and email scopes
userRouter.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect(`${process.env.FRONTEND_URL}/`); // Redirect to your frontend URL
  }
);

// Email verification
userRouter.get('/sendEmail', sendVerificationEmail);

// Forgot and Reset Password
userRouter.post('/forgotpassword', forgotPassword);
userRouter.post('/resetpassword', resetPassword);

// User details and profile update
userRouter.get('/details', authMiddleware, userDetails); // Changed to GET for user details retrieval
userRouter.patch('/update', userUpdate);

export default userRouter;
