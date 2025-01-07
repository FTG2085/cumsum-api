const scraper = require('./scraper')
const dates = require('date-fns')
const Joi = require('joi')
const dotenv = require('dotenv')
const logging = require('../logging')
dotenv.config({ path: '../.env' })

function registerLogMethods(expressApp, validateAuthorization, getActionUser, UserData) {
    expressApp.post('/logs/new', validateAuthorization, getActionUser, async (req, res) => {

        let log = req.body

        const logSchema = Joi.object({
            sauce: Joi.object({
                site: Joi.string().uri().required(),
                tags: Joi.alternatives().try(
                    Joi.valid('scraper'),
                    Joi.array().items(Joi.string())
                ).required()
            }),
            sessionTime: Joi.number()
        })

        const result = logSchema.validate(log)

        if (result.error) {
            logging('post', '/logs/new', 422, 'Invalid or expire token!', req.ip, req.user.username)
            res.status(422).send('Invalid log format!')
        } else {
            if (req.actionUser.relation == 'other' && !req.admin) {
                logging('post', '/logs/new', 403, 'You do not have permission to log for other users!', req.ip, req.user.username)
                return res.status(403).send('You do not have permission to log for other users!')
            }

            if (log.sauce.tags == 'scraper') {
                log.sauce.tags = await scraper.scrapeTags(log.sauce.site)
            }
            let user = UserData.getUserData(req.actionUser.user)
            let date = new Date()
            log.timestamp = date.getTime()
            if (!user.logs[dates.format(date, 'MM-yyyy')]) {
                user.logs[dates.format(date, 'MM-yyyy')] = []
            }
            user.logs[dates.format(date, 'MM-yyyy')].push(log)
            UserData.setUserData(req.actionUser.user, user)

            res.status(200).json({ message: 'Successfully logged!', log})
            logging('post', '/logs/new', 200, 'Successfully logged!', req.ip, req.user.username)
        }
    })

    expressApp.get('/logs/view', validateAuthorization, (req, res) => {
        let user = UserData.getUserData(req.actionUser.user)
        if (user.logsPublic || req.admin) {
            if (req.query.filter) {
                if (!user.logs[req.query.filter]) {
                    logging('get', '/logs/view', 404, 'No logs were found!', req.ip, req.user.username)
                    return res.status(404).send('No logs were found!')
                }
                logging('get', '/logs/view', 200, 'Success!', req.ip, req.user.username)
                return res.status(200).json({ message: 'Success!', logs: user.logs[req.query.filter] })
            
            } else {
                logging('get', '/logs/view', 200, 'Success!', req.ip, req.user.username)
                return res.status(200).json({ message: 'Success!', logs: user.logs })
            }
        } else {
            logging('get', '/logs/view', 403, "User's profile is set to private!", req.ip, req.user.username)
            res.status(403).send("User's profile is set to private!")
        }
    })
}

module.exports = {
    registerLogMethods
}