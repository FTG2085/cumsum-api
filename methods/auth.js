const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const Joi = require('joi')
const fs = require('fs')
const axios = require('axios')
const dotenv = require('dotenv')
const logging = require('../logging')
dotenv.config({ path: '../.env' })

function registerAuthMethods(expressApp, validateToken, UserData) {
    expressApp.post('/auth/login', async (req, res) => {
        // Returns if no username or password was entered
        if (!req.body.username || !req.body.password) {
            logging('post', '/auth/login', 400, 'Username or password was not provided!', req.ip)
            return res.status(400).send('Username or password was not provided!')
        }
        
        // Creates an instance of the Auth Database and returns if the username or password is wrong
        const { username, password } = req.body
        const userID = UserData.getUserID(username)
        if (!UserData.usernameExists(username)) {
            logging('post', '/auth/login', 401, 'Invalid username or password!', req.ip)
            return res.status(401).send('Invalid username or password!') 
        } 
        if (!bcrypt.compareSync(password, UserData.getPasswordHash(userID))) return res.status(401).send('Invalid username or password!'); logging('post', '/auth/login', 401, 'Invalid username or password!', req.ip)
        
        // Signs a token 
        const token = jwt.sign({ username, userID }, process.env.JWT_SECRET, { expiresIn: '14d'} )
    
        // Sends a cookie containing the token to the browser if applicable
        res.cookie('auth-token', token, {
            httpOnly: true,
            maxAge: 43200000, // 12 Hours
            sameSite: 'strict'
        })
    
        // Sends the token back to the client
        res.json({ message: 'Login successful!', token })
        logging('post', '/auth/login', 200, 'Login successful!', req.ip)
    })
    
    expressApp.post('/auth/register', async (req, res) => {
        // If username or password is not present, returns.
        if (!req.body.username || !req.body.password) {
            logging('post', '/auth/register', 400, 'Username or password was not provided!', req.ip)
            return res.status(400).send('Username or password was not provided!');
        }

        // Create schema to restrict username and passwords
        const schema = Joi.object({
            username: Joi
                .string()
                .regex(/^[a-zA-Z0-9]+([._][a-zA-Z0-9]+)*$/)
                .max(30)
                .min(3)
                .required(),
            password: Joi
                .string()
                .max(100)
                .min(8)
        })
    
        const result = schema.validate(req.body) // Make sure request has valid data
    
        // Return if invalid username/password
        if (result.error) {
            logging('post', '/auth/register', 400, 'Username or password was not provided!', req.ip)
            return res.status(422).send('Invalid username/password!')
        }
    
        // Prepares the data to be added to the database
        const { username, password } = req.body
        const passwordHash = bcrypt.hashSync(password, 10)   // Hash the password
    
        // Checks if username already exists
        if (UserData.usernameExists(username)) return res.send('Username already exists!')
        
        // Adds user to database
        UserData.addUser(username, passwordHash)
        res.send('User created successfully!')
        logging('post', '/auth/register', 200, 'User created successfully!', req.ip)
    })

    expressApp.get('/auth/discord/start', validateToken, (req, res) => {
        if (!req.query.redirect) {
            logging('get', '/auth/discord/start', 400, 'Missing URI redirect!', req.ip, req.user.username)
            return res.status(400).send('Missing URI redirect!')
        }
        const oauthRefs = JSON.parse(fs.readFileSync('./database/oauthReferences.json'))
        const referenceID = crypto.randomUUID()
        const state = { ref: referenceID, r: req.query.redirect }
        oauthRefs[referenceID] = req.token
        fs.writeFileSync('./database/oauthReferences.json' ,JSON.stringify(oauthRefs))

        const { CLIENT_ID, REDIRECT_URI } = process.env

        const oauthURL = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=identify+email&state=${encodeURIComponent(Buffer.from(JSON.stringify(state)).toString('base64'))}`
        res.status(200).json({ message: 'Success!', url: oauthURL })
    })

    expressApp.get('/auth/discord/callback', (req, res) => {
        if (!req.query.code) {
            logging('get', '/auth/discord/callback', 400, 'Missing authorization code!', req.ip)
            return res.status(400).send('Missing authorization code!')
        }
        if (!req.query.state) {
            logging('get', '/auth/discord/callback', 400, 'Missing state!', req.ip)
            return res.status(400).send('Missing state!')
        }

        const state = JSON.parse(Buffer.from(req.query.state, 'base64').toString('utf-8'))
        let oauthRefs = JSON.parse(fs.readFileSync('./database/oauthReferences.json'))
        let token
        if (oauthRefs[state.ref]) {
            token = oauthRefs[state.ref]
            delete oauthRefs[state.ref]
            fs.writeFileSync('./database/oauthReferences.json', JSON.stringify(oauthRefs))
        } else {
            logging('get', '/auth/discord/callback', 401, 'Invalid token reference!', req.ip)
            return res.status(401).send('Invalid token reference!')
        }
        let redirect = state.r

        jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
            if (err) {
                logging('get', '/auth/discord/callback', 401, 'Invalid or expire token!', req.ip)
                return res.status(401).send('Invalid or expired token')
            }

            const { CLIENT_SECRET, CLIENT_ID, REDIRECT_URI } = process.env
        
            try {
                const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({

                    code: req.query.code,
                    grant_type: 'authorization_code',
                    redirect_uri: REDIRECT_URI,
                }).toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, auth: { username: CLIENT_ID, password: CLIENT_SECRET } })
                .catch((err) => {
                    console.log(err)
                })
        
                const { access_token, refresh_token } = tokenResponse.data
        
                const userResponse = await axios.get('https://discord.com/api/v10/users/@me', {
                    headers: {
                        Authorization: `Bearer ${access_token}`,
                    },
                })
        
                const { id, username, email } = userResponse.data
                let userData = UserData.getUserData(user.userID)
                userData.auth.discord = {
                    accessToken: access_token,
                    refresh_token: refresh_token
                }
                userData.info.discord = {
                    id, username, email
                }
                UserData.setUserData(user.userID, userData)
                
                res.redirect(redirect)
            } catch (err) {
                console.error(err)
            }
        })
        
    })
}

module.exports = {
    registerAuthMethods
}