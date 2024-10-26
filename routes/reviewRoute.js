import express from 'express'
import { addReview, listReview, removeReview } from '../controllers/reviewController.js'
import multer from 'multer'

const reviewRouter = express.Router();





reviewRouter.post('/add',addReview)
reviewRouter.get('/list',listReview)
reviewRouter.post('/remove', removeReview)

export default reviewRouter;