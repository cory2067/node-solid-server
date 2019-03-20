module.exports = handler;

const fs = require('fs');
const $rdf = require('rdflib');

const allow = require('../allow');
const utils = require('../../utils.js');

const seal = require("./sealjs");
const shell = require('shelljs');
const request = require('request');

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
async function authenticatedHandler (req, res, next) {
  const ldp = req.app.locals.ldp
  const baseUri = utils.getFullUri(req)
  const root = !ldp.multiuser ? ldp.root : ldp.root + req.hostname + '/'

  console.log("Processing this request:");
  console.log(req.body);

  if (!req.body.query || !req.body.aggregatorKey || !req.body.researcherKey) {
    return res.status(400).send("missing params");
  }

  // download required certs
  try {
    await Promise.all([
      download(req.body.aggregatorKey, __dirname + '/aggpublic.pem'),
      download(req.body.researcherKey, __dirname + '/respublic.key')
    ]);
  } catch (err) {
    console.log(err)
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

  const queryString = `
      PREFIX foaf: <http://xmlns.com/foaf/0.1/>
      SELECT ?age
      WHERE {
          ?user foaf:age ?age;
                foaf:gender ?gender.
          FILTER (?gender = "male")
      }
  `;
  // add to paper: if no match, treat it as filter=0
  const a = await findSingle(queryString, store);
  console.log(a);

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
  const pk = new seal.PublicKey(__dirname + "/respublic.key");

  const filter = 1; // TODO replace with real thing

  // encode the value as a polynomial
  const encoder = new seal.Encoder(65536);
  const plainValue = new seal.Plaintext(encoder, parseInt(value));
  const plainFilter = new seal.Plaintext(encoder, parseInt(filter));

  // encrypt the polynomial and save
  const encryptor = new seal.Encryptor(context, pk);
  const cipherValue = new seal.Ciphertext(encryptor, plainValue);
  const cipherFilter = new seal.Ciphertext(encryptor, plainFilter);

  cipherValue.save(__dirname + "/value.seal");
  cipherFilter.save(__dirname + "/filter.seal");
  console.log("encrypted first layer");

  // kinda janky, but this calls an encryption script
  // that bundles together the value and filter and encrypts with A
  shell.exec(`${__dirname}/bundle`);
  
  return res.sendFile(__dirname + "/bundle.enc");
}

// download a file, returns a promise
function download(uri, filename) {
  return new Promise((resolve, reject) => {
    request.head(uri, function(err, res, body){
      console.log('content-type:', res.headers['content-type']);
      console.log('content-length:', res.headers['content-length']);

      if (err) return reject(err);
      if (res.statusCode !== 200) return reject(res.statusCode);
      request(uri).pipe(fs.createWriteStream(filename)).on('close', resolve);
    });
  });
}

// query string: has exactly 1 variable
function findSingle(queryString, store) {
	return new Promise((resolve, reject) => {
		const sq = $rdf.SPARQLToQuery(queryString, false, store);
    const desiredVar = `?${sq.vars[0].label}`;

		store.query(sq, (row) => {
      // return the first row if match
		  resolve(row[desiredVar].value);
		}, {}, () => {
      // resolves undefined if nothing matched
      resolve();
		});
	});
}
