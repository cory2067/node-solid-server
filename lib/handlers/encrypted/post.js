module.exports = handler;

const fs = require('fs');
const $rdf = require('rdflib')

const allow = require('../allow')
const utils = require('../../utils.js')

const seal = require("./sealjs")
const shell = require('shelljs');

// Runs whenever a POST /encrypted request is received
// Makes sure the user has 
function handler (req, res, next) { 
  allow('Write')(req, res, (err, b) => {
    if (err) {
      return res.status(401).send("You cannot perform this operation");
    }

    authenticatedHandler(req, res, next);
  })
}

// Runs when POST /encrypted has been authenticated
// response: status 200 if a valid query and valid files are given
//           empty string if no match was found
//           32kb encrypted binary if a match was found
function authenticatedHandler (req, res, next) {
  const ldp = req.app.locals.ldp
  const baseUri = utils.getFullUri(req)
  const root = !ldp.multiuser ? ldp.root : ldp.root + req.hostname + '/'

  console.log("Processing this request:");
  console.log(req.body);

  if (!req.body.query) {
    return res.status(400).send("400 Bad Request (no query)");
  }

  const query = $rdf.sym(req.body.query);
  const docs = req.body.docs;

  // Load files into memory
  // (note: this isn't very scalable to many/large files) 
  const store = $rdf.graph();
  for (const doc of docs) {
    if (doc === '') continue;
    const localPath = doc.split(req.headers.host)[1];
    if (!localPath) {
      return res.status(400).send("File does not belong to your pod");
    }

    // Read file as a string
    let data;
    try {
      data = fs.readFileSync(utils.uriToFilename(localPath, root)).toString();
    } catch (err) {
      // the user gave us a path that doesn't exist
      return res.status(404).send(localPath);
    }

    // Load file into memory
    try {
      $rdf.parse(data, store, baseUri, 'text/turtle', () => {
        console.log("LOADED file "  + localPath);
      }); 
    } catch (err) {
      // this file was probably poorly formatted or not valid ttl
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
  if (isNaN(value)) {
    return res.status(500).send("expected numeric, got " + value);
  }

  // encrypt with homomorphic encryption
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
  
  return res.sendFile(cipherPath + ".enc");
}
