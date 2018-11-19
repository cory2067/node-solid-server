module.exports = handler

const fs = require('fs')
const glob = require('glob')
const _path = require('path')
const $rdf = require('rdflib')
const Negotiator = require('negotiator')
const url = require('url')
const mime = require('mime-types')

const debug = require('debug')('solid:get')
const debugGlob = require('debug')('solid:glob')
const allow = require('../allow')

const utils = require('../../utils.js')
const translate = require('../../utils.js').translate
const error = require('../../http-error')

const RDFs = require('../../ldp').RDF_MIME_TYPES
const LegacyResourceMapper = require('../../legacy-resource-mapper')

function handler (req, res, next) {
  const ldp = req.app.locals.ldp
  const includeBody = req.method === 'GET'
  const negotiator = new Negotiator(req)
  const baseUri = utils.getFullUri(req)
  const path = res.locals.path || req.path
  const requestedType = negotiator.mediaType()
  let possibleRDFType = negotiator.mediaType(RDFs)
  
  // Fallback to text/turtle if content type is unknown
  possibleRDFType = (!possibleRDFType) ? 'text/turtle' : possibleRDFType

  res.header('MS-Author-Via', 'SPARQL')
  debug(req.originalUrl + ' on ' + req.hostname)

  const options = {
    'hostname': req.hostname,
    'path': path,
    'baseUri': baseUri,
    'includeBody': includeBody,
    'possibleRDFType': possibleRDFType,
    'range': req.headers.range
  }

  const root = !ldp.multiuser ? ldp.root : ldp.root + req.hostname + '/'
  const accessPath = "/private/enc-access.txt"; // accessible file list 
  const access = fs.readFileSync(utils.uriToFilename(accessPath, root)).toString();

  // list of all accessible paths to query
  const to_search = access.split("\n").map(path => utils.uriToFilename(path, root));

  if (!req.query.q) {
    return res.status(400).send("400 Bad Request (no query)");
  }
  const query = $rdf.sym(req.query.q);

  const store = $rdf.graph();

  // populate memory with all to_search files
  for (const doc of to_search) {
    const data = fs.readFileSync(doc).toString();
    try {
      $rdf.parse(data, store, baseUri, 'text/turtle', () => {
        console.log("LOADED file "  + doc);
      }); 
    } catch (err) {
      return res.status(500).send("could not open file for reading");
    }
  }
 
  // currently only matches by predicate 
  const result = store.match(undefined, query);
  if (!result.length) {
    return res.send("query not found");
  }

  // extract value
  const value = result[0].object.value;
  /*if (isNaN(value)) {
    return res.status(500).send("expected numeric, got " + value);
  }*/

  return res.send(value);
}

// TODO: get rid of this ugly hack that uses the Allow handler to check read permissions
function hasReadPermissions (file, req, res, callback) {
  const ldp = req.app.locals.ldp

  if (!ldp.webid) {
    return callback(true)
  }

  const root = ldp.multiuser ? ldp.root + req.hostname + '/' : ldp.root
  const relativePath = '/' + _path.relative(root, file)
  res.locals.path = relativePath
  allow('Read')(req, res, err => callback(!err))
}
