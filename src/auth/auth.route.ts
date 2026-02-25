import { Router } from 'express';
import { login, register } from './auth.controller';

const router = Router();

router.post('/api/auth/register', register);
router.post('/api/auth/login', login);

export default router;
