const { UserData } = require('../userdata')
const scraper = require('./scraper')
const dates = require('date-fns')
const Joi = require('joi')
const dotenv = require('dotenv')
const permissions = require('./permissions')
dotenv.config({ path: '../.env' })

function registerLogMethods(expressApp, validateAuthorization) {
    expressApp.post('/logs/new', validateAuthorization, async (req, res) => {
        const permissionUserID = permissions.getUser(req)
        if (permissionUserID.messagee !== undefined) return res.status(permissionUserID.messagee.code).send(permissionUserID.messagee.msg)

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
            if (log.sauce.tags == 'scraper') {
                log.sauce.tags = await scraper.scrapeTags(log.sauce.site)
            }
            let dataInstance = new UserData()
            let user = dataInstance.getUserData(req.user.userID)
            let date = new Date()
            log.timestamp = date.getTime()
            if (!user.logs[dates.format(date, 'MM-yyyy')]) {
                user.logs[dates.format(date, 'MM-yyyy')] = []
            }
            user.logs[dates.format(date, 'MM-yyyy')].push(log)
            dataInstance.setUserData(req.user.userID, user)

            res.status(200).json({ message: 'Successfully logged!', log})
        }
    })

    expressApp.get('/logs/view', validateAuthorization, (req, res) => {

        let dataInstance = new UserData()

        if (req.query.u) {
            if (!dataInstance.usernameExists(req.query.u)) return res.status(404).send('User not found!')
        } else if (req.query.uId) {
            if (!dataInstance.userIdExists(req.query.uID)) return res.status(404).send('User not found!')
        } else {
            return res.status(422).send('No user was provided!')
        }
        let user = dataInstance.getUserData(req.query.u ? dataInstance.getUserID(req.query.u) : req.query.uId)
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