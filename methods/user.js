const Joi = require('joi')
const { UserData } = require('../userdata')
const permissions = require('./permissions')
const dotenv = require('dotenv')
dotenv.config({ path: '../.env' })

function registerUserMethods(expressApp, validateToken) {

    expressApp.get('/user/settings', validateToken, (req, res) => {
        const permissionUserID = permissions.getUser(req)
        if (permissionUserID.messagee !== undefined) return res.status(permissionUserID.messagee.code).send(permissionUserID.messagee.msg)

        let dataInstance = new UserData()
        let userSettings = dataInstance.getUserData(permissionUserID.result).settings

        res.status(200).json({ message: 'Success!', settings: userSettings })
    })

    expressApp.patch('/user/settings/edit', validateToken, (req, res) => {
        const schema = Joi.object({
            logsPublic: Joi.bool()
        })

        const result = schema.validate(req.body)

        if (result.error) return res.status(422).send('Invalid settings object!')
        
        const permissionUserID = permissions.getUser(req)
        if (permissionUserID.messagee !== undefined) return res.status(permissionUserID.messagee.code).send(permissionUserID.messagee.msg)

        let dataInstance = new UserData()
        const data = dataInstance.getUserData(permissionUserID.result)
        data.settings = {...data.settings, ...result.value}
        dataInstance.setUserData(permissionUserID.result, data)
        res.status(200).json({ message: 'Success!', settings: data.settings })
    })

    expressApp.get('/user/info', validateToken, (req, res) => {
        const permissionUserID = permissions.getUser(req)
        if (permissionUserID.messagee !== undefined) return res.status(permissionUserID.messagee.code).send(permissionUserID.messagee.msg)

        let dataInstance = new UserData()
        let userInfo = dataInstance.getUserData(permissionUserID.result).info

        res.status(200).json({ message: 'Success!', info: userInfo })
    })
}

module.exports = {
    registerUserMethods
}