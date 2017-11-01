import express from 'express';
import User from '../models/User';
import parseErrors from '../utils/parseErrors';

const router = express.Router();

router.post('/', (req, res) => {
  const { credentials } = req.body;
  User.findOne({ email: credentials.email }).then((user) => {
    if (user && user.isValidPassword(credentials.password)) {
      res.json({ user: user.toAuthJSON() });
    } else {
      res.status(400).json({ errors: { global: 'Invalid credentials' } });
    }
  });
});

router.post('/confirmation', (req, res) => {
  const { token } = req.body;
  User.findOneAndUpdate(
    { confirmationToken: token },
    { confirmationToken: '', confirmed: true },
    { new: true },
  ).then((user) => {
    res.json({ user: user.toAuthJSON() });
  })
    .catch(err => res.status(400).json({ errors: parseErrors(err.errors) }));
});

export default router;
