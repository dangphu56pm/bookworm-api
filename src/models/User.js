import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// add uniqueness and email validateions to email field
const schema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      lowercase: true,
    },
    passwordHash: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  },
);

schema.methods.isValidPassword = function isValidPassword(password) {
  return bcrypt.compareSync(password, this.passwordHash);
};

schema.methods.generateJWT = function generateJWT() {
  return jwt.sign(
    {
      email: this.email,
    },
    process.env.JWT_SECRET,
  );
};

schema.methods.toAuthJSON = function toAuthJSON() {
  return {
    email: this.email,
    token: this.generateJWT(),
  };
};

export default mongoose.model('User', schema);
