import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import rateLimit from 'express-rate-limit'
import mongoose from 'mongoose'
import authRoutes from './routes/auth.js'

dotenv.config({ path: './config.env' })

const app = express()
const PORT = process.env.PORT || 5000

// Middleware
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}))

app.use(express.json())

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
})
app.use('/api/', limiter)

// Routes
app.use('/api/auth', authRoutes)
app.get('/api/dashboard/summary', async (req, res) => {
  try {
    // Placeholder: aggregate data when podcast/clip models exist
    res.json({
      episodes: 3,
      clips: 4,
      contentMinutes: 175,
      shorts: 2
    })
  } catch (e) {
    res.status(500).json({ message: 'Unable to load dashboard' })
  }
})
// Simple billing routes (credits)
app.post('/api/billing/purchase', async (req, res) => {
  try {
    const { userId, credits } = req.body
    if (!userId || !credits || credits <= 0) return res.status(400).json({ message: 'userId and positive credits required' })
    const { User } = await import('./models/User.js')
    const user = await User.findById(userId)
    if (!user) return res.status(404).json({ message: 'User not found' })
    user.credits += Number(credits)
    await user.save()
    res.json({ message: 'Credits added', credits: user.credits })
  } catch (e) {
    console.error('Purchase error:', e)
    res.status(500).json({ message: 'Unable to add credits' })
  }
})

app.post('/api/billing/consume', async (req, res) => {
  try {
    const { userId, cost } = req.body
    if (!userId || !cost || cost <= 0) return res.status(400).json({ message: 'userId and positive cost required' })
    const { User } = await import('./models/User.js')
    const user = await User.findById(userId)
    if (!user) return res.status(404).json({ message: 'User not found' })
    if (user.credits < cost) return res.status(402).json({ message: 'Insufficient credits' })
    user.credits -= Number(cost)
    await user.save()
    res.json({ message: 'Credits consumed', credits: user.credits })
  } catch (e) {
    console.error('Consume error:', e)
    res.status(500).json({ message: 'Unable to consume credits' })
  }
})

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Podcast Clipper AI API is running' })
})

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  })
})

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' })
})

// Connect to MongoDB then start server
async function start() {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is not set in config.env')
    }
    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: process.env.MONGODB_DB || undefined
    })
    console.log('✅ Connected to MongoDB')

    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`)
      console.log(`📡 API available at http://localhost:${PORT}/api`)
    })
  } catch (err) {
    console.error('❌ Failed to start server:', err.message)
    process.exit(1)
  }
}

start()
