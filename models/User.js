
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  discordId: {
    type: String,
    unique: true,
    sparse: true
  },
  username: {
    type: String,
    required: true,
    unique: true
  },
  discriminator: String,
  avatar: String,
  email: {
    type: String,
    unique: true,
    sparse: true
  },
  password: String,
  vouchCount: {
    type: Number,
    default: 0
  },
  serverVouches: {
    type: Map,
    of: Number,
    default: {}
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('User', userSchema);
