const Loki = require('lokijs')
const dotenv = require('dotenv')
const path = require('path')
dotenv.config()

class UserData {
    constructor() {
        this.db = new Loki(path.join(process.env.DATABASE_PATH, 'userdata.db'), {
            autoload: true,
            autoloadCallback: this.initializeDatabase,
            autosave: true,
            autosaveInterval: 4000
        })
    }

    initializeDatabase = () => {
        this.users = this.db.getCollection('users')
        if (this.users === null) {
            this.users = this.db.addCollection('users')
        }
    }

    getPasswordHash(userID) {
        const user = this.users.findOne({ '$loki': userID })
        return user.auth.password
    }

    getUserData(userID) {
        return this.users.findOne({ '$loki': userID })
    }

    getUserID(username) {
        const user = this.users.findOne({ 'info.username': username })
        return user ? user.$loki : null
    }

    userIdExists(userID) {
        return this.users.findOne({ '$loki': userID }) !== null
    }

    usernameExists(username) {
        return this.users.findOne({ 'info.username': username }) !== null
    }

    addUser(username, passwordHash) {
        const newUser = {
            auth: {
                username,
                password: passwordHash
            },
            settings: {
                logsPublic: true
            },
            info: {
                username,
                role: 'MEMBER',
                badges: [],
                createdTime: Date.now()
            },
            logs: {}
        }
        this.users.insert(newUser)
    }

    setUserData(userID, data) {
        const user = this.users.findOne({ '$loki': userID })
        if (user) {
            Object.assign(user, data)
            this.users.update(user)
        }
    }
}

module.exports = { UserData }