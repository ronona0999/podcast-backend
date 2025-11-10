import express from 'express'
import bcrypt from 'bcryptjs'
import { User, generateOTP } from '../models/User.js'
import { generateToken, authenticateToken } from '../middleware/auth.js'
import { sendOtpEmail } from '../utils/mailer.js'
import crypto from 'crypto'
import { OAuth2Client } from 'google-auth-library'

const router = express.Router()

// Signup endpoint
router.post('/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body

    // Validation
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ 
        message: 'All fields are required' 
      })
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        message: 'Password must be at least 6 characters long' 
      })
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(409).json({ 
        message: 'User with this email already exists' 
      })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12)

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword
    })

    // Generate OTP
    const otp = generateOTP()
    user.setOTP(otp)
    await user.save()

    // Send OTP email
    await sendOtpEmail({ to: email, name: firstName, otp })

    res.status(201).json({
      message: 'User created successfully. Please check your email for verification code.',
      user: user.publicJSON(),
      otp: process.env.NODE_ENV === 'development' ? otp : undefined // Only show OTP in development
    })
  } catch (error) {
    console.error('Signup error:', error)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Login endpoint
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body

    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        message: 'Email and password are required' 
      })
    }

    // Find user
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(401).json({ 
        message: 'Invalid email or password' 
      })
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password)
    if (!isPasswordValid) {
      return res.status(401).json({ 
        message: 'Invalid email or password' 
      })
    }

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(401).json({ 
        message: 'Please verify your email before logging in' 
      })
    }

    // Generate token
    const token = generateToken({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName
    })

    res.json({
      message: 'Login successful',
      token,
      user: user.publicJSON()
    })
  } catch (error) {
    console.error('Login error:', error)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Verify OTP endpoint
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body

    // Validation
    if (!email || !otp) {
      return res.status(400).json({ 
        message: 'Email and OTP are required' 
      })
    }

    // Find user
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(404).json({ 
        message: 'User not found' 
      })
    }

    // Verify OTP
    const isOTPValid = user.verifyOTP(otp)
    if (!isOTPValid) {
      return res.status(400).json({ 
        message: 'Invalid or expired OTP' 
      })
    }

    await user.save()

    // Generate token
    const token = generateToken({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName
    })

    res.json({
      message: 'Email verified successfully',
      token,
      user: user.publicJSON()
    })
  } catch (error) {
    console.error('OTP verification error:', error)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Verify token endpoint
router.post('/verify-token', async (req, res) => {
  try {
    const { token } = req.body

    if (!token) {
      return res.status(400).json({ 
        message: 'Token is required' 
      })
    }

    // In a real app, you would verify the JWT token here (left as-is in middleware)
    // For this endpoint, just check if any user exists in DB to simulate
    const anyUser = await User.findOne()
    res.json({ valid: Boolean(anyUser) })
  } catch (error) {
    console.error('Token verification error:', error)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Resend OTP endpoint
router.post('/resend-otp', async (req, res) => {
  try {
    const { email } = req.body
    if (!email) {
      return res.status(400).json({ message: 'Email is required' })
    }
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }
    const otp = generateOTP()
    user.setOTP(otp)
    await user.save()
    await sendOtpEmail({ to: email, name: user.firstName, otp })
    res.json({ message: 'OTP resent successfully' })
  } catch (error) {
    console.error('Resend OTP error:', error)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Protected route example
router.get('/profile', authenticateToken, (req, res) => {
  res.json({
    message: 'This is a protected route',
    user: req.user
  })
})

export default router

// Current user details from DB
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
    if (!user) return res.status(404).json({ message: 'User not found' })
    res.json({ user: user.publicJSON() })
  } catch (e) {
    console.error('Get me error:', e)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Forgot Password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body
    if (!email) return res.status(400).json({ message: 'Email is required' })
    const user = await User.findOne({ email })
    if (!user) return res.status(200).json({ message: 'If that email exists, a reset email has been sent' })
    const token = crypto.randomBytes(32).toString('hex')
    user.resetPasswordToken = token
    user.resetPasswordExpires = new Date(Date.now() + 30 * 60 * 1000)
    await user.save()
    const resetUrl = `${process.env.CLIENT_BASE_URL || 'http://localhost:3000'}/reset-password?token=${token}&email=${encodeURIComponent(email)}`
    await sendPasswordResetEmail({ to: email, name: user.firstName, resetUrl })
    res.json({ message: 'Password reset email sent' })
  } catch (e) {
    console.error('Forgot password error:', e)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Reset Password
router.post('/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body
    if (!email || !token || !newPassword) return res.status(400).json({ message: 'Email, token and newPassword required' })
    const user = await User.findOne({ email, resetPasswordToken: token, resetPasswordExpires: { $gt: new Date() } })
    if (!user) return res.status(400).json({ message: 'Invalid or expired token' })
    const hashed = await bcrypt.hash(newPassword, 12)
    user.password = hashed
    user.resetPasswordToken = null
    user.resetPasswordExpires = null
    await user.save()
    res.json({ message: 'Password has been reset' })
  } catch (e) {
    console.error('Reset password error:', e)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Google Login
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)
router.post('/google', async (req, res) => {
  try {
    const { idToken } = req.body
    if (!idToken) return res.status(400).json({ message: 'idToken required' })

    const ticket = await googleClient.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID })
    const payload = ticket.getPayload()
    const email = payload.email
    const googleId = payload.sub
    const firstName = payload.given_name || 'User'
    const lastName = payload.family_name || ''

    let user = await User.findOne({ email })
    if (!user) {
      user = await User.create({
        email,
        firstName,
        lastName,
        password: 'google-oauth',
        isVerified: true,
        provider: 'google',
        googleId,
        credits: 10
      })
    } else if (!user.isVerified) {
      user.isVerified = true
      await user.save()
    }

    const token = generateToken({ id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName })
    res.json({ message: 'Login successful', token, user: user.publicJSON() })
  } catch (err) {
    console.error('Google auth error:', err)
    res.status(500).json({ message: 'Unable to login with Google' })
  }
})
