module.exports = LdpMiddleware

const express = require('express')
const header = require('./header')
const allow = require('./handlers/allow')
const get = require('./handlers/get')
const post = require('./handlers/post')
const put = require('./handlers/put')
const del = require('./handlers/delete')
const patch = require('./handlers/patch')
const index = require('./handlers/index')
const copy = require('./handlers/copy')

const encryptedPost = require('./handlers/encrypted/post')

function LdpMiddleware (corsSettings) {
  const router = express.Router('/')

  // Add Link headers
  router.use(header.linksHandler)

  if (corsSettings) {
    router.use(corsSettings)
  }

  router.post('/encrypted', encryptedPost);

  router.copy('/*', allow('Write'), copy)
  router.get('/*', index, allow('Read'), header.addPermissions, get)
  router.post('/*', allow('Append'), post)
  router.patch('/*', allow('Append'), patch)
  router.put('/*', allow('Write'), put)
  router.delete('/*', allow('Write'), del)

  return router
}
