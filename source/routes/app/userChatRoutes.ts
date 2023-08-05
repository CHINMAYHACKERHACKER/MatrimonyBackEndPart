import express from 'express';
import controller from '../../controllers/app/userChat';

const router = express.Router();

router.post('/userChat',controller.insertUserChat);

router.post('/getUserChatList',controller.getUserChatList)

export = router;