import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { prisma } from '../lib/prisma';
import { redis } from '../lib/redis';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret';
const RegisterSchema = z.object({
  email: z
    .string()
    .trim()
    .toLowerCase()
    .email('please provide a valid email address'),
  password: z
    .string()
    .min(8, 'password must be at least 8 characters long')
    .max(72, 'password must be at most 72 characters long')
    .regex(/[a-z]/, 'password must include at least one lowercase letter')
    .regex(/[A-Z]/, 'password must include at least one uppercase letter')
    .regex(/[0-9]/, 'password must include at least one number')
    .regex(/[^A-Za-z0-9]/, 'password must include at least one special character')
    .regex(/^\S+$/, 'password must not contain spaces'),
});

export const register = async (req: Request, res: Response) => {
  const parsedInput = RegisterSchema.safeParse(req.body);
  if (!parsedInput.success) {
    return res.status(400).json({
      error: 'invalid request body',
      details: parsedInput.error.issues.map((issue) => ({
        field: issue.path.join('.'),
        message: issue.message,
      })),
    });
  }
  const { email, password } = parsedInput.data;

  const existingUser = await prisma.user.findUnique({
    where: { email },
    select: { id: true },
  });

  if (existingUser) {
    return res.status(409).json({ error: 'user already exists' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await prisma.user.create({
    data: { email, passwordHash },
  });

  return res.status(201).json({ message: 'user registered' });
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body as { email?: string; password?: string };

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const user = await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, passwordHash: true },
  });

  if (!user) {
    return res.status(401).json({ error: 'invalid credentials' });
  }

  const isValidPassword = await bcrypt.compare(password, user.passwordHash);
  if (!isValidPassword) {
    return res.status(401).json({ error: 'invalid credentials' });
  }

  const token = jwt.sign({ sub: user.email, email: user.email }, JWT_SECRET, {
    expiresIn: '1h',
  });

  return res.status(200).json({ token });
};
