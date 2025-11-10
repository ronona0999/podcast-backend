import nodemailer from 'nodemailer'

function createTransport() {
  const host = process.env.SMTP_HOST
  const port = Number(process.env.SMTP_PORT || 587)
  const secure = String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true'
  const user = process.env.SMTP_USER
  const pass = process.env.SMTP_PASS

  if (!host || !user || !pass) {
    throw new Error('SMTP configuration is missing. Please set SMTP_HOST, SMTP_USER, SMTP_PASS in config.env')
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass }
  })
}

export async function sendOtpEmail({ to, name, otp }) {
  const transporter = createTransport()
  const from = process.env.SMTP_FROM || 'Podcast Clipper AI <no-reply@example.com>'

  const html = `
    <div style="font-family:system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;">
      <h2>Verify your email</h2>
      <p>Hi ${name || ''},</p>
      <p>Your one-time password (OTP) for Podcast Clipper AI is:</p>
      <div style="font-size:24px;font-weight:700;letter-spacing:4px;margin:16px 0;">${otp}</div>
      <p>This code will expire in 10 minutes. If you did not request this, you can ignore this email.</p>
      <p style="color:#6b7280;">Thanks,<br/>Podcast Clipper AI Team</p>
    </div>
  `

  const text = `Your Podcast Clipper AI OTP is ${otp}. It expires in 10 minutes.`

  await transporter.sendMail({ from, to, subject: 'Your OTP Code', text, html })
}

export async function sendPasswordResetEmail({ to, name, resetUrl }) {
  const transporter = createTransport()
  const from = process.env.SMTP_FROM || 'Podcast Clipper AI <no-reply@example.com>'
  const html = `
    <div style="font-family:system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;">
      <h2>Reset your password</h2>
      <p>Hi ${name || ''},</p>
      <p>Click the link below to reset your password. This link expires in 30 minutes.</p>
      <p><a href="${resetUrl}" target="_blank">Reset Password</a></p>
      <p>If you did not request this, you can ignore this email.</p>
      <p style="color:#6b7280;">Thanks,<br/>Podcast Clipper AI Team</p>
    </div>
  `
  const text = `Reset your password: ${resetUrl}`
  await transporter.sendMail({ from, to, subject: 'Reset your password', text, html })
}


