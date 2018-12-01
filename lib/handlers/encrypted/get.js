module.exports = handler

const fs = require('fs')
const seal = require("./sealjs")
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

  // Load the enc-access.ttl file
  const accessList = "/private/enc-access.ttl";
  const data = fs.readFileSync(utils.uriToFilename(accessList, root)).toString();
  const accessStore = $rdf.graph();
  $rdf.parse(data, accessStore, baseUri, "text/turtle", () => {
    console.log("LOADED file " + accessList);
  });

  // Query files that this aggregator has access too
  const aggregatorUri = $rdf.sym("https://enc.localhost:8443/public/card#me");
  const ENC = $rdf.Namespace('http://enc.test/');
  const resultAccess = accessStore.match(aggregatorUri, ENC('reads'));

  if (!req.query.q) {
    return res.status(400).send("400 Bad Request (no query)");
  }
  const query = $rdf.sym(req.query.q);

  // Load all files thta we have access to open
  const store = $rdf.graph();
  for (const doc of resultAccess) {
    const localPath = doc.object.value.split(req.headers.host)[1];
    const data = fs.readFileSync(utils.uriToFilename(localPath, root)).toString();
    try {
      $rdf.parse(data, store, baseUri, 'text/turtle', () => {
        console.log("LOADED file "  + localPath);
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

  // encrypt with homomorphic encryption
  const context = new seal.SEALContext(2048, 128, 65536);
  const pk = new seal.PublicKey(__dirname + "/public.key");

  // encode the value as a polynomial
  const encoder = new seal.Encoder(65536);
  const plain = new seal.Plaintext(encoder, parseInt(value));

  // encrypt the polynomial and save
  const encryptor = new seal.Encryptor(context, pk);
  const ciphertext = new seal.Ciphertext(encryptor, plain);
  ciphertext.save(__dirname + "/value.seal");

  return res.sendFile(__dirname + "/value.seal");
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
