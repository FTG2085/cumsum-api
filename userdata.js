const fs = require('fs')
const path = require('path')

class UserData {
    #newInstance() {
        return JSON.parse(fs.readFileSync(path.join(__dirname, 'database', 'userdata.json')))
    }

    #saveInstance(instance) {
        return fs.writeFileSync(path.join(__dirname, 'database', 'userdata.json'), JSON.stringify(instance))
    }

    getPasswordHash(userID) {
        let dataInstance = this.#newInstance()
        return dataInstance[userID].auth.password
    }

    getUserData(userID) {
        let dataInstance = this.#newInstance()
        return dataInstance[userID]
    }

    getUserID(username) {
        let dataInstance = this.#newInstance()
        for (let i = 0; i < dataInstance.length; i++) {
            if (dataInstance[i].info.username == username) {
                return i
            }
        }
    }

    userIdExists(userID) {
        let dataInstance = this.#newInstance()
        return dataInstance.length >= userID
    }

    usernameExists(username) {
        let dataInstance = this.#newInstance()
        let exists = false
        dataInstance.forEach(user => {
            if (user.info.username == username) exists = true
        })
        return exists
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
            }
        }
        let dataInstance = this.#newInstance()
        dataInstance.push(newUser)
        this.#saveInstance(dataInstance)
    }

    setUserData(userID, data) {
        let dataInstance = this.#newInstance()
        dataInstance[userID] = data
        this.#saveInstance(dataInstance)
    }

}

module.exports = { UserData }