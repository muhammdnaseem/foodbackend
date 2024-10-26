import express from 'express'
import { addDeal, listDeal, removeDeal } from '../controllers/dealController.js'


const dealRouter = express.Router();



dealRouter.post('/add',addDeal)
dealRouter.get('/list',listDeal)
dealRouter.post('/remove', removeDeal)

export default dealRouter;