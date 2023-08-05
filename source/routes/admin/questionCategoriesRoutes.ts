import express from 'express';
import controller from '../../controllers/admin/questionCategories';

const router = express.Router();

router.post('/getQuestion',controller.getQuestion)

router.post('/insertUpdateQuestionCategories',controller.insertUpdateQuestionCategories)

router.post('/activeInactiveQuestionCategories',controller.activeInactiveQuestionCategories)

router.post('/deleteQuestionCategories',controller.deleteQuestionCategories)

router.post('/insertUpdateQuestion',controller.insertUpdateQuestion)

router.post('/activeInactiveQuestion',controller.activeInactiveQuestion)

router.post('/deleteQuestion',controller.deleteQuestion)

export = router;