import express from 'express';
import { Express } from 'express';
import healthRoute from './health/health.route';

const app: Express = express();

// Middleware
app.use(express.json());

// Routes
app.use(healthRoute)

export default app;

