
const mongoose = require('mongoose');

const vouchSchema = new mongoose.Schema({
  fromUserID: {
    type: String,
    required: true
  },
  toUserID: {
    type: String,
    required: true
  },
  serverID: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

// Prevent duplicate vouches from the same user in the same server
vouchSchema.index({ fromUserID: 1, toUserID: 1, serverID: 1 }, { unique: true });

module.exports = mongoose.model('Vouch', vouchSchema);
