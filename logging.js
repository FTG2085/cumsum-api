const chalk = require('chalk')

function logRequest(method, path, code, message, ip, user) {
  console.log(`${chalk.blue(method.toUpperCase())} ${chalk.green(path)} - ${code.toString().startsWith('4') ? chalk.redBright(code) : chalk.greenBright(code)} ${chalk.yellowBright(message)} - ${user ? chalk.cyan(user) : chalk.cyan(ip)}`)
}
module.exports = logRequest