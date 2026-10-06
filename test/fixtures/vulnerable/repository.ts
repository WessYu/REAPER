import { PrismaClient } from '@prisma/client';
import { Pool } from 'pg';
const prisma = new PrismaClient();
const pool = new Pool();
export function order(id: string) {
  return prisma.order.findUnique({where: {id}});
}
export function search(value: string) {
  const sql = 'SELECT * FROM orders WHERE title = ' + value;
  return pool.query(sql);
}
