import express from 'express'
import { addCategory, listCategory, removeCategory } from '../controllers/categoryController.js'
import multer from 'multer'

const categoryRouter = express.Router();

// Image Storage Engine

const storage = multer.diskStorage({
    destination:"uploads/categories",
    filename: (req,file,cb)=>{
        return cb(null,`${Date.now()}${file.originalname}`)
    }
})

const upload = multer({storage:storage})
categoryRouter.post('/add',upload.single('categoryImage'),addCategory)
categoryRouter.get('/list',listCategory)
categoryRouter.post('/remove', removeCategory)

export default categoryRouter;