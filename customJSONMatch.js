const hm = require('header-metadata')
const sm = require('service-metadata')
const util = require('util')
const ms = require('multistep')
sm.setVar('var://service/mpgw/skip-backside', true)
const main = async () => {
    const rawBody = session.input
    const body = await util.promisify((rawBody, callback) => rawBody.readAsJSON(callback))(rawBody)
    if (!body) {
        throw new Error('Invalid JSON')
    }
    const messageName = body.securityHeader.messageName
    if (!messageName) {
        throw new Error('Invalid messageName')
    }
    const callRuleAsync = util.promisify(ms.callRule.bind(ms));
    const callRuleError = await callRuleAsync(messageName, session.input,session.output)
    if (callRuleError) {
        throw new Error(callRuleError)
    }
}

main().catch((error) => {
    console.error(error)
    session.output.write({ error: error.message })
})