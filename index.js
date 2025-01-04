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

dotenv.config()

const PORT = process.env.PORT
const JWT_SECRET = process.env.JWT_SECRET

const app = express()

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 75,
    standardHeaders: 'draft-8',
    legacyHeaders: false
})

app.use(express.json())
app.use(cookieParser())
app.use(limiter)

const authenticateToken = (req, res, next) => {
    // If cookie or authorization header is not present, return
    if (!req.cookies['auth-token'] && !req.headers['authorization'] && !req.query.token) return res.status(401).send('Unauthorized!')
    
    // Set token to either query, cookie, or header (header has priority)
    let token
    if (req.query.token) { token = req.query.token }
    if (req.cookies['auth-token']) { token = req.cookies['auth-token'] }
    if (req.headers['authorization']) { token = req.headers['authorization'] } 
    req.token = token

    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, user) => {
        const userData = new UserData()
        if (err) { return res.status(401).send('Invalid or expired token. ' + err) }
        const userID = userData.getUserID(user.username)
        delete userData
        // Pass token data to request
        req.user = user
        req.admin = false

        if (req.query.admin == 'true') {
            if (userData.getUserData(user.userID).info.role == 'ADMIN') {
                req.admin = true
            }
        }

        next()
    })
}

app.get('/ip', (request, response) => response.send(request.ip))

auth.registerAuthMethods(app, authenticateToken)
user.registerUserMethods(app, authenticateToken)
scraper.registerScrapeMethod(app, authenticateToken)
nutLogs.registerLogMethods(app, authenticateToken)

app.listen(PORT, () => {
    console.log(`Listening on http://localhost:${PORT}`)
})

module.exports = {
    UserData
}