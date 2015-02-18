// SHA Digest Web Cryptography API Example Code Snippet
// (see http://www.w3.org/TR/WebCryptoAPI/)
//
// The code demonstrates the following functionality:
// * generate a SHA-1 checksum
//
// Hint: Internet Explorer 11 supports the webcrypto-api but has a non-standard promises implementation,
// therefore you have to change the code to work in IE 11 or use a proper polyfill.
//
// This example makes also use of the JS encoding API (https://encoding.spec.whatwg.org/)
// A proper polyfill for other browsers is "text-encoding" (https://github.com/inexorabletash/text-encoding)
//
// snippet by: innoq.com, simon.koelsch
//
// check the result for example with:
// perl -e 'use Digest::SHA qw(sha1_hex); print sha1_hex("this is a text to hash")."\n"'

// --- just a helper function for debug purposes
// converts an arraybuffer containing Uint8Array data to a hexstring
function ab2hex(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var hex = "";
  for (var i=0; i<byteArray.byteLength; i++) {
    hex += byteArray[i].toString(16);
  }
  return hex;
}

var encoder = new TextEncoder("utf-8");

var cryptoSubtle = window.crypto.subtle;
var algorithm = {name: 'SHA-1'};

var toHash = "this is a text to hash";

data = encoder.encode(toHash);

cryptoSubtle.digest(algorithm, data)
.then(function(hash) {
  console.log("string",toHash,"hashed with", algorithm.name,":", ab2hex(hash));
});
