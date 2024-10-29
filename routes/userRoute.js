import express from 'express';
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



// Initiate Google login
userRouter.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));


// Google callback route
userRouter.get(
  '/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    const user = req.user;
    
    if (user) {
      // Generate a JWT token
      const token = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Send the token as a JSON response
      res.status(200).json({ success: true, token });
    } else {
      res.status(401).json({ success: false, message: 'Authentication failed' });
    }
  }
);

// Initiate Facebook login
userRouter.get('/auth/facebook', passport.authenticate('facebook', { scope: 'email' }));


// Google callback route
userRouter.get(
  '/auth/facebook/callback',
  passport.authenticate('facebook', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    const user = req.user;
    
    if (user) {
      // Generate a JWT token
      const token = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Send the token as a JSON response
      res.status(200).json({ success: true, token });
    } else {
      res.status(401).json({ success: false, message: 'Authentication failed' });
    }
  }
);


userRouter.post('/sendEmail', sendDirectVerificationEmail);




// Forgot and Reset Password
userRouter.post('/forgotpassword', forgotPassword);
userRouter.post('/resetpassword', resetPassword);

// User details and profile update
userRouter.get('/details', authMiddleware, userDetails); // Changed to GET for user details retrieval
userRouter.patch('/update', userUpdate);

export default userRouter;
