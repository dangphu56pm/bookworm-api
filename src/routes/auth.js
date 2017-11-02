import express from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import parseErrors from '../utils/parseErrors';
import { sendResetPasswordRequest } from '../mailer';

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

router.post('/reset_password_request', (req, res) => {
  User.findOne({ email: req.body.email }).then((user) => {
    if (user) {
      sendResetPasswordRequest(user);
      res.json({});
    } else {
      res.status(400).json({ errors: { global: 'There is no user with such email ' } });
    }
  });
});

router.post('/validate_token', (req, res) => {
  jwt.verify(req.body.token, process.env.JWT_SECRET, (err) => {
    if (err) {
      res.stats(401).json({});
    } else {
      res.json({});
    }
  });
});

export default router;
