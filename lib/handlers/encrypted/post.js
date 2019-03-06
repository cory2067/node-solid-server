module.exports = handler;

const fs = require('fs');
const $rdf = require('rdflib')

const allow = require('../allow')
const utils = require('../../utils.js')

const seal = require("./sealjs")
const shell = require('shelljs');

function handler (req, res, next) { 
  console.log(req.session);
  allow('Read')(req, res, (err, b) => {
    console.log("do we have permissions?");
    console.log(err, b); 
    if (err) {
        return res.status(401).send("you cannot access this");
    }

    authenticatedHandler(req, res, next);
  })
}

function authenticatedHandler (req, res, next) {
  const ldp = req.app.locals.ldp
  const baseUri = utils.getFullUri(req)

  console.log(req.body);
  const root = !ldp.multiuser ? ldp.root : ldp.root + req.hostname + '/'

  if (!req.body.query) {
    return res.status(400).send("400 Bad Request (no query)");
  }
  const query = $rdf.sym(req.body.query);
  const docs = req.body.docs;
  console.log(docs);

  // Load all files thta we have access to open
  // THIS IS NOT SCALABLE _AT ALL_
  const store = $rdf.graph();
  for (const doc of docs) {
    if (doc === '') continue;
    const localPath = doc.split(req.headers.host)[1];
    if (!localPath) {
        return res.status(400).send("File does not belong to your pod");
    }

    let data;
    try {
        data = fs.readFileSync(utils.uriToFilename(localPath, root)).toString();
    } catch (err) {
        return res.status(404).send(localPath);
    }

    try {
      $rdf.parse(data, store, baseUri, 'text/turtle', () => {
        console.log("LOADED file "  + localPath);
      }); 
    } catch (err) {
      return res.status(500).send("Could not parse turtle file");
    }
  }

  // currently only matches by predicate 
  const result = store.match(undefined, query);
  if (!result.length) {
    // no match -> return empty string
    return res.status(200).send("");
  }

  // extract value
  const value = result[0].object.value;
  /*if (isNaN(value)) {
    return res.status(500).send("expected numeric, got " + value);
  }*/

  // encrypt with homomorphic encryption
  console.log("ENCRYPTION BEGIN");
  const context = new seal.SEALContext(2048, 128, 65536);
  const pk = new seal.PublicKey(__dirname + "/public.key");

  // encode the value as a polynomial
  const encoder = new seal.Encoder(65536);
  const plain = new seal.Plaintext(encoder, parseInt(value));

  // encrypt the polynomial and save
  const encryptor = new seal.Encryptor(context, pk);
  const ciphertext = new seal.Ciphertext(encryptor, plain);
  const cipherPath = __dirname + "/value.seal";
  ciphertext.save(cipherPath);
  console.log("encrypted first layer");

  // kinda janky, but this calls an encryption script
  shell.exec(`${__dirname}/encrypt`);
  
  console.log("Returning!");
  return res.sendFile(cipherPath + ".enc");
}
