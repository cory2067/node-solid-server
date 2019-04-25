module.exports = handler;

const fs = require('fs');
const $rdf = require('rdflib');

const allow = require('../allow');
const utils = require('../../utils.js');

const seal = require("./sealjs");
const shell = require('shelljs');
const request = require('request');

// Runs whenever a POST /encrypted request is received
// Verifies the user has sufficient permissions
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
//           ~64kb encrypted binary if a match was found
async function authenticatedHandler (req, res, next) {
  const ldp = req.app.locals.ldp;
  const baseUri = utils.getFullUri(req);
  const root = !ldp.multiuser ? ldp.root : ldp.root + req.hostname + '/';

  console.log("Processing this request:");
  console.log(req.body);

  if (!req.body.study || !req.body.docs) {
    return res.status(400).send("missing params");
  }

  // download required certs
  const id = req.sessionID; // tack on some id, in case there are concurrent requests
  try {
    await Promise.all([
      download(req.body.study.aggKey, `${__dirname}/aggpublic${id}.pem`),
      download(req.body.study.key, `${__dirname}/respublic${id}.key`)
    ]);
  } catch (err) {
    console.log(err)
    return res.status(404).send("certs not found");
  }

  // the files we're allowed to read to extract the desired value
  const docs = req.body.docs;
  
  // Load all specified files into memory
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

  // e.g. ratio(?age > 10)
  const queryString = req.body.study.query;
  
  // parses a study.function
  /* 
   * group 1: function name
   * group 2: variable name
   * group 4: operator (or undef)
   * group 5: int literal
  */
  const funcRegex = /([a-zA-Z]+)\((\?[a-zA-Z]+)(\s*([<>=])\s*([0-9]+))?\)/;
  const match = req.body.study.function.match(funcRegex);
  const [_x, fnName, fnVar, _y, fnOperator, fnLiteral] = match;

  // add to paper: if no match, treat it as filter=0
  const queryResult = await findVariable(queryString, fnVar, store);

  let filter = (queryResult !== undefined) ? 1 : 0;
  let value = (queryResult || 0);

  if (filter && fnOperator && fnLiteral) { // a comparison was specified
    console.log("Checking if field " + fnOperator + " " + fnLiteral);
    switch (fnOperator) {
      case ">":
        value = (value > parseInt(fnLiteral)) ? 1 : 0;
        break;

      case "<":
        value = (value < parseInt(fnLiteral)) ? 1 : 0;
        break;

      case "=":
        value = (value === parseInt(fnLiteral)) ? 1 : 0;
        break;

      default :
        // something messed up, void this result
        filter = 0;
        value = 0;
    }
  }
 
  console.log(`Found V=${value} F=${filter}`);

  // encrypt with homomorphic encryption
  const context = new seal.SEALContext(2048, 128, 65536);
  const pk = new seal.PublicKey(`${__dirname}/respublic${id}.key`);

  // encode the value as a polynomial
  const encoder = new seal.Encoder(65536);
  const plainValue = new seal.Plaintext(encoder, parseInt(value));
  const plainFilter = new seal.Plaintext(encoder, parseInt(filter));

  // encrypt the polynomial and save
  const encryptor = new seal.Encryptor(context, pk);
  const cipherValue = new seal.Ciphertext(encryptor, plainValue);
  const cipherFilter = new seal.Ciphertext(encryptor, plainFilter);

  // kind of annoying to need to save an intermediate file
  cipherValue.save(`${__dirname}/value${id}.seal`);
  cipherFilter.save(`${__dirname}/filter${id}.seal`);
  console.log("encrypted first layer");

  // kinda janky, but this calls an encryption script
  // that bundles together the value and filter and encrypts with A
  shell.exec(`${__dirname}/bundle ${id}`);
 
  // Client downloads bundle, and then we can delete it 
  const bundlePath = `${__dirname}/bundle${id}.enc`;
  const file = fs.createReadStream(bundlePath);
  file.on('end', function() {
    fs.unlink(bundlePath, function() {
      console.log("cleanup complete");
    });
  });
  file.pipe(res);
}

// download a file, returns a promise
function download(uri, filename) {
  return new Promise((resolve, reject) => {
    request.head(uri, function(err, res, body){
      if (err) return reject(err);

      console.log('content-type:', res.headers['content-type']);
      console.log('content-length:', res.headers['content-length']);

      if (res.statusCode !== 200) return reject(res.statusCode);
      request(uri).pipe(fs.createWriteStream(filename)).on('close', resolve);
    });
  });
}

// execute a sparql query on store, returning the value of the desiredVar
function findVariable(queryString, desiredVar, store) {
	return new Promise((resolve, reject) => {
		const sq = $rdf.SPARQLToQuery(queryString, false, store);

		store.query(sq, (row) => {
      // return the first row if match
		  resolve(row[desiredVar].value);
		}, {}, () => {
      // resolves undefined if nothing matched
      resolve();
		});
	});
}
