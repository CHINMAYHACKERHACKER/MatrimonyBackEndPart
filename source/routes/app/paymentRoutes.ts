import express from 'express';
import controller from '../../controllers/app/payment';

const router = express.Router();

router.post('/insertPayment',controller.insertPaymentRazorpay);

router.post('/insertPaymentStripe',controller.insertPaymentStripe)

export = router;