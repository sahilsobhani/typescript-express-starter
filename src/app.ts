import express from 'express';
import { Express } from 'express';
import healthRoute from './health/health.route';
import authRoute from './auth/auth.route';

const app: Express = express();

// Middleware
app.use(express.json());

// Routes
app.use(healthRoute)
app.use(authRoute)

export default app;

