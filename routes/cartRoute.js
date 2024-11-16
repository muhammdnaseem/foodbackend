import express from 'express'
import { addToCart, removeFromCart, getCart, updateCart, deleteItemFromCart } from '../controllers/cartController.js'
import authMiddleware from '../middleware/auth.js';

const cartRouter = express.Router();

cartRouter.post("/add", authMiddleware, addToCart)
cartRouter.post("/remove",authMiddleware, removeFromCart)
cartRouter.post("/update",authMiddleware, updateCart)
cartRouter.get("/get",authMiddleware, getCart)

cartRouter.delete("/delete",authMiddleware, deleteItemFromCart)


export default cartRouter;
