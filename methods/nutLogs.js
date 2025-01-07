const scraper = require('./scraper')
const dates = require('date-fns')
const Joi = require('joi')
const dotenv = require('dotenv')
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
            res.status(422).send('Invalid log format!')
        } else {
            if (req.actionUser.relation == 'other' && !req.admin) {
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
        }
    })

    expressApp.get('/logs/view', validateAuthorization, (req, res) => {
        let user = UserData.getUserData(req.actionUser.user)
        if (user.logsPublic || req.admin) {
            if (req.query.filter) {
                if (!user.logs[req.query.filter]) return res.status(404).send('No logs were found!')
                return res.status(200).json({ message: 'Success!', logs: user.logs[req.query.filter] })
            } else {
                return res.status(200).json({ message: 'Success!', logs: user.logs })
            }
        } else {
            res.status(403).send("User's profile is set to private!")
        }
    })
}

module.exports = {
    registerLogMethods
}