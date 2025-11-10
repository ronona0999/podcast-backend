import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, index: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  provider: { type: String, enum: ['local', 'google'], default: 'local' },
  googleId: { type: String, default: null },
  credits: { type: Number, default: 0 },
  resetPasswordToken: { type: String, default: null },
  resetPasswordExpires: { type: Date, default: null },
  otp: { type: String, default: null },
  otpExpiresAt: { type: Date, default: null }
}, { timestamps: true })

userSchema.methods.setOTP = function(otp) {
  this.otp = otp
  this.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000)
}

userSchema.methods.verifyOTP = function(otp) {
  if (!this.otp || !this.otpExpiresAt) return false
  if (new Date() > this.otpExpiresAt) {
    this.otp = null
    this.otpExpiresAt = null
    return false
  }
  if (this.otp === otp) {
    this.isVerified = true
    this.otp = null
    this.otpExpiresAt = null
    return true
  }
  return false
}

userSchema.methods.publicJSON = function() {
  return {
    id: this._id,
    firstName: this.firstName,
    lastName: this.lastName,
    email: this.email,
    isVerified: this.isVerified,
    createdAt: this.createdAt
  }
}

export const User = mongoose.model('User', userSchema)

export function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString()
}
