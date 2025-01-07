// Require dependencies
const express = require('express')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const dotenv = require('dotenv')
const { UserData } = require('./userdata')
const { rateLimit } = require('express-rate-limit')

const auth = require('./methods/auth')
const user = require('./methods/user')
const nutLogs = require('./methods/nutLogs')
const scraper = require('./methods/scraper')

// Load environment variables
dotenv.config()

const PORT = process.env.PORT
const JWT_SECRET = process.env.JWT_SECRET

// Initialize express app
const app = express()
//app.set('trust proxy', 1)

// Rate limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 75,
    standardHeaders: 'draft-8',
    legacyHeaders: false
})

// Middleware
app.use(express.json())
app.use(cookieParser())
app.use(limiter)

// Initialize database
const userData = new UserData()
userData.initializeDatabase()

// Authentication middleware
const authenticateToken = (req, res, next) => {
    // If cookie or authorization header is not present, return
    if (!req.cookies['auth-token'] && !req.headers['authorization'] && !req.query.token) return res.status(401).send('Unauthorized!')
    
    // Set token to either query, cookie, or header (header has priority)
    let token
    if (req.query.token) token = req.query.token 
    if (req.cookies['auth-token']) token = req.cookies['auth-token'] 
    if (req.headers['authorization']) token = req.headers['authorization'].split(' ')[1] 
    req.token = token

    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) { return res.status(401).send('Invalid or expired token. ') }

        // Pass token data to request
        req.user = user
        next()
    })
}

const getActionUser = (req, res, next) => {
    let user = req.user.userID
    let actionUser = { user: 0, relation: '' }

    if (req.query.u) {
        if (!userData.usernameExists(req.query.u)) return res.status(404).send('User not found!')
        actionUser.user = userData.getUserID(req.query.u)
        actionUser.user == user ? actionUser.relation = 'self' : actionUser.relation = 'other'
    } else if (req.query.uID) {
        if (!userData.userIdExists(req.query.uID)) return res.status(404).send('User not found!')
        actionUser.user = req.query.uID
        actionUser.user == user ? actionUser.relation = 'self' : actionUser.relation = 'other'
    } else if (req.params.u) { 
        if (!userData.usernameExists(req.params.u)) return res.status(404).send('User not found!')
        actionUser.user = userData.getUserID(req.params.u)
        actionUser.user == user ? actionUser.relation = 'self' : actionUser.relation = 'other'
    } else {
        actionUser.user = user
        actionUser.relation = 'self'
    }

    if (userData.getUserData(req.user.userID).info.role === 'ADMIN' && req.query.admin === 'true') {
        req.admin = true
        actionUser.relation = 'self'
    } else {
        req.admin = false
    }

    req.actionUser = actionUser
    next()
}

// IP endpoint
app.get('/ip', (request, response) => response.send(request.ip))

// Register methods
auth.registerAuthMethods(app, authenticateToken, userData)
user.registerUserMethods(app, authenticateToken, getActionUser, userData)
scraper.registerScrapeMethod(app, authenticateToken)
nutLogs.registerLogMethods(app, authenticateToken, getActionUser, userData)

// Start server
app.listen(PORT, () => {
    console.log(`Listening on http://localhost:${PORT}`)
})