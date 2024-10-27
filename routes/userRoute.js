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


// Google authentication routes
// Initiate Google login
userRouter.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google OAuth callback
userRouter.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Generate JWT and redirect to frontend with token
    const token = generateJWT(req.user);
    res.redirect(`http://localhost:5173/auth/google/callback?token=${token}`);
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
