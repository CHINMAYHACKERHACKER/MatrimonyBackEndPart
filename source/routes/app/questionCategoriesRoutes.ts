import express from 'express';
import controller from '../../controllers/app/questionCategories'

const router = express.Router();

router.post('/getQuestion',controller.getQuestion)

export = router;