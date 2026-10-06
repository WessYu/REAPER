import express from 'express';
import { PrismaClient } from '@prisma/client';
import { Pool } from 'pg';
const app = express();
const prisma = new PrismaClient();
const pool = new Pool();
app.get('/orders/:id', (req, res) => {
  return prisma.order.findUnique({where: {id: req.params.id, userId: req.user.id, organizationId: req.user.organizationId}});
});
app.get('/search', (req, res) => pool.query('SELECT * FROM orders WHERE title = $1', [req.query.title]));
app.get('/tag', (req, res) => prisma.$queryRaw`SELECT * FROM orders WHERE id = ${req.params.id}`);
