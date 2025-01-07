const Joi = require('joi')
const dotenv = require('dotenv')
const logging = require('../logging')
dotenv.config({ path: '../.env' })

function registerUserMethods(expressApp, validateToken, getActionUser, UserData) {

    expressApp.get('/user/settings', validateToken, getActionUser, (req, res) => {
        let userSettings = UserData.getUserData(req.actionUser.user).settings

        if (req.actionUser.relation === 'other' && !req.admin) {
            logging('get', '/user/settings', 403, 'You do not have permission to view other users settings!', req.ip, req.user.username)
            return res.status(403).send('You do not have permission to view other users settings!')
        }
        logging('get', '/user/settings', 200, 'Success!', req.ip, req.user.username)
        res.status(200).json({ message: 'Success!', settings: userSettings })
    })

    expressApp.patch('/user/settings/edit', validateToken, getActionUser, (req, res) => {

        const schema = Joi.object({
            logsPublic: Joi.bool()
        })

        const result = schema.validate(req.body)

        if (result.error) return res.status(422).send('Invalid settings object!')

        if (req.actionUser.relation === 'other' && !req.admin) {
            logging('patch', '/user/settings/edit', 403, 'You do not have permission to edit other users settings!', req.ip, req.user.username)
            return res.status(403).send('You do not have permission to edit other users settings!')
        }

        const data = UserData.getUserData(req.actionUser.user)
        data.settings = {...data.settings, ...result.value}
        UserData.setUserData(req.actionUser.user, data)
        logging('patch', '/user/settings/edit', 200, 'Success!', req.ip, req.user.username)
        res.status(200).json({ message: 'Success!', settings: data.settings })
    })

    expressApp.get('/user/info', validateToken, getActionUser, (req, res) => {
        let userInfo = UserData.getUserData(req.actionUser.user).info

        if (req.actionUser.relation == 'other') {
            if(userInfo.discord) {
                delete userInfo.discord.email
            }
        }

        logging('get', '/user/info', 200, 'Success!', req.ip, req.user.username)
        res.status(200).json({ message: 'Success!', info: userInfo })
    })
}

module.exports = {
    registerUserMethods
}