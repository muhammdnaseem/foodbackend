import express from "express";
import { stripePayment,verifyPayment } from "../controllers/paymentController.js";

const paymentRouter = express.Router();

paymentRouter.post("/add", stripePayment); // Stripe payment route
paymentRouter.post("/verifypayment", verifyPayment)


export default paymentRouter;
