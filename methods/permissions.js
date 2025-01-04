const { UserData } = require('../userdata')

function getUser(req) {
    let dataInstance = new UserData()

    let user
    let message
    
    // Gets the correct user ID and returns if user does not exist or missing permissions
    if (req.query.u) {
        if (!dataInstance.usernameExists(req.query.u)) { 
            message = { code: 404, msg: 'User does not exist!' }
            user = false
        }

        if (req.admin) {
            user = dataInstance.getUserID(req.query.u)
        } else if (req.query.u == req.user.username) {
            user = dataInstance.getUserID(req.query.u)
        } else {
            message = { code: 403, msg: 'Missing permission!' }
            user = false
        }
    } else if (req.query.uID) {
        if (!dataInstance.userIdExists(req.query.uID)) {
            message = { code: 404, msg: 'User does not exist!' }
            user = false
        }

        if (req.admin) {
            user = req.query.uID
        } else if (req.query.uID == req.user.userID) {
            user = req.query.uID
        } else {
            message = { code: 403, msg: 'Missing permission!' }
            user = false
        }
    } else {
        user = req.user.userID
    }
    return {
        result: user,
        message
    }
}

module.exports = {
    getUser
}