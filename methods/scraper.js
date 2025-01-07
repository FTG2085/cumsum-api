const cheerio = require('cheerio')
const fs = require('fs')
const { URL } = require('node:url')
const axios = require('axios')
const dotenv = require('dotenv')
const logging = require('../logging')
dotenv.config({ path: '../.env' })

async function scrapeTags(url) {
    const site = new URL(url)
    const content = await axios.get(url, { headers: { "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}})
    const $ = await cheerio.load(content.data)

    let tagArr = []

    function findTagsBySelector(selector) {
        let tags = []
        $(selector).each((index, element) => {
            tags.push($(element).html().toLowerCase())
        })
        tags = tags.map(tag => tag.replace(/<[^>]*>/g, '').trim())
        return tags
    }

    function checkAgainstKeywords(word) {
        const keywords = JSON.parse(fs.readFileSync('keywords.json'))
        for (let key in keywords ) {
            if (keywords[key].includes(word)) {
                return key
            }
        }

        return null
    }

    function scrapeForAnything() {
        let tags = []
        $('title').text().toLowerCase().split(' ').forEach((word) => {
            let keyword = checkAgainstKeywords(word)
            if (keyword!=null) tags.push(keyword)
        })
        $('.tag-type-general a').each((index, element) => {
            if ($(element).attr('href').includes('?page=post')) tags.push($(element).text().toLowerCase())
        })
        tags.concat(findTagsBySelector('a[href^="/tags/"]'))
        tags.concat(findTagsBySelector('a[href^="/tag/"]'))

        if (tags == []) {
            return null
        } else {
            tags = tags.map(tag => tag.replace(/<[^>]*>/g, '').trim())
            return tags
        }
    }
    
    switch (true) {
        case site.hostname.includes('pornhub.com'):
            tagArr = findTagsBySelector('.categoriesWrapper a')
            break
        case site.hostname.includes('rule34.xxx') || site.hostname.includes('gelbooru.com'):
            let tags = []
            $('.tag-type-general a').each((index, element) => {
                if ($(element).attr('href').includes('?page=post')) tags.push($(element).html().toLowerCase().replace(/<[^>]*>/g, ''))
            })
            tagArr = tags
            break
        case site.hostname.includes('xvideos.com'):
            tagArr = findTagsBySelector('a[href^="/tags/"]')
            break
        case site.hostname.includes('xnxx.com'):
            tagArr = findTagsBySelector('a.is-keyword')
            break
        case site.hostname.includes('nhentai.net'):
            tagArr = findTagsBySelector('a[href^="/tag/"] span.name')
            break
        case site.hostname.includes('hanime.tv'):
            tagArr = findTagsBySelector('a[href^="/browse/tags/"] div.btn__content')
            break
        case site.hostname.startsWith('x.com'):
            tagArr = findTagsBySelector('.r-18u37iz a').map(tag => tag.slice(1))
            break
        default:
            tagArr = scrapeForAnything()
            break
    }

    return tagArr 

}

function registerScrapeMethod(expressApp, validateToken) {
    expressApp.get('/scraper', validateToken, (req, res) => {
        if (!req.query.url) {
            logging('get', '/scraper', 422, 'No url provided!', req.ip, req.user.username)
            return res.status(422).send('No url provided!')
        }
        const tags = scrapeTags(decodeURIComponent(req.query.url))
        logging('get', '/scraper', 200, 'Success!', req.ip, req.user.username)
        res.status(200).json({ message: 'Success!', tags })
    })
}


module.exports = {
    scrapeTags,
    registerScrapeMethod
}