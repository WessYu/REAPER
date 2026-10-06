import express from 'express';
import { order, search } from './repository.js';
const app = express();
app.get('/orders/:id', (req, res) => {
  return order(req.params.id);
});
app.get('/search', (req, res) => search(req.query.title));
