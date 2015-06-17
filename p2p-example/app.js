// Small Webcrypto API demo by sending encrypted and/or signed messages via websockets
// (see http://www.w3.org/TR/WebCryptoAPI/)
//
// A browser with decent webRTC and ecma script 6 support is needed, for example firefox or chrome
//
// snippet by: innoq.com, simon.koelsch, christoph.iserlohn

var demo = demo || {};

demo.crypto = {};
demo.out = {};

demo.keypair = null;
demo.encryptionKey = null;
demo.decryptionKey = null;
demo.verificationKey = null;
demo.doMITM = false;
demo.shouldSign = false;
demo.shouldVerify = false;
demo.shouldEncrypt = false;
demo.shouldDecrypt = false;

demo.server = "ws://localhost:20500";

demo.connect = function(server) {

	demo.out.serverlog("connecting to " + server + " ...");
	demo.socketNode = P.create().connect(server);

	demo.socketNode.on('open', function() {
		demo.out.serverlog("connection ready")
		alertify.success("Connected to "+server);
	});
	demo.socketNode.on('close', function() {
		demo.out.serverlog("connection closed")
		alertify.success("Connection to "+server + " closed");
	});
	demo.socketNode.on('error', function() {
		demo.out.serverlog("connection error (" + server + ")")
		alertify.error("connection error: "+ server);
	});
	demo.socketNode.on('message', function(msg) {demo.out.serverlog("got message: " + msg)});

	demo.socketNode.on('connection', function(peer) {
		demo.out.p2plog("got connection from "+peer.address);
		alertify.success("got connection from "+peer.address);

		demo.peer = peer;
		peer.on('message', demo.handleMessage);
	});
};

demo.connectPeer = function(peer) {

	demo.peer = demo.socketNode.connect(peer);

	demo.peer.on('open', function() {demo.out.p2plog("P2P connection ready")});
	demo.peer.on('close', function() {demo.out.p2plog("P2P connection closed")});
	demo.peer.on('error', function() {demo.out.p2plog("P2P connection error")});
};

demo.generateKeypair = function() {

	console.log("generating keypair for algorithm: ", demo.crypto.keypairAlgorithm);

	var extractable = true;
	var usages = ['sign', 'verify'];

        demo.crypto.subtle.generateKey(demo.crypto.keypairAlgorithm, extractable, usages)
	.then(function(keypair) {
		demo.storeKeypair(keypair);
		console.log("keypair generated");
		alertify.success("keypair generated");
	}).catch(function(error) {
		console.log(error);
		alertify.error(error);
	});
};

demo.generateEncryptionKey = function() {

	console.log("generating key for algorithm: ", demo.crypto.keyAlgorithm);

	var extractable = true;
	var usages = ['encrypt', 'decrypt'];

        demo.crypto.subtle.generateKey(demo.crypto.keyAlgorithm, extractable, usages)
	.then(function(key) {
		demo.storeEncryptionKey(key);
		console.log("key generated");
		alertify.success("key generated");
	}).catch(function(error) {
		console.log(error);
		alertify.error(error);
	});
};

demo.storeKeypair = function (keypair) {

	demo.keypair = keypair;
	console.log("generated keypair: " + keypair)
	
	demo.crypto.subtle.exportKey('jwk', keypair.publicKey)
	.then(function(exportedKey) {
		jQuery("#jwk-public-key").text(JSON.stringify(exportedKey));
	}).catch(function (error) {
		console.log(error);
		alertify.error(error);
	});
};

demo.storeEncryptionKey = function (key) {

	demo.encryptionKey = key;
	console.log("generated encryption key: " + key)
	
	demo.crypto.subtle.exportKey('jwk', key)
	.then(function(exportedKey) {
		jQuery("#jwk-crypto-key").text(JSON.stringify(exportedKey));
	}).catch(function (error) {
		console.log(error);
		alertify.error(error);
	});
};


demo.clearKeys = function () {
	demo.keypair = null;
	demo.encryptionKey = null;
	demo.verificationKey = null;
	demo.decryptionKey = null;
	demo.encryptionKey = null;
}

demo.importPublicKey = function(jwkJson) {

	try {
		var jwk = JSON.parse(jwkJson);

		console.log("JSON parsed for JWK import");

		var extractable = true;
		var usages = ['verify'];

		demo.crypto.subtle.importKey("jwk", jwk, demo.crypto.keypairAlgorithm, extractable, usages)
		.then(function(keyImport) {
			demo.verificationKey = keyImport;
			console.log("key imported");
			alertify.success("key imported");
		}).catch(function(error) {
			console.log(error);
			alertify.error(error);
		});

	} catch(error) {
		console.log(error);
		alertify.error(error);
	}
};

demo.importDecryptionkey = function(jwkJson) {

	try {
		var jwk = JSON.parse(jwkJson);

		console.log("JSON parsed for JWK import");

		var extractable = true;
		var usages = ['decrypt'];

		demo.crypto.subtle.importKey("jwk", jwk, demo.crypto.keyAlgorithm, extractable, usages)
		.then(function(keyImport) {
			demo.decryptionKey = keyImport;
			console.log("key imported");
			alertify.success("key imported");
		}).catch(function(error) {
			console.log(error);
			alertify.error(error);
		});

	} catch(error) {
		console.log(error);
		alertify.error(error);
	}
};

demo.MITM = function(message) {
	return message.replace(/a/ig, 'e');
};

demo.sendMessage = function(msg) {

	var sendFn = function(messageObject) {
		demo.peer.send(messageObject);
		demo.out.p2plogOut(msg);
	}

        demo.packAndSendMessage(msg, demo.encryptionKey, demo.keypair, sendFn);
};

demo.packAndSendMessage = function(msg, key, keypair, sendFn) {

	var messageObject = {'message' : msg, 'signature' : null};

	var msgBuffer = demo.encoder.encode(msg);

	if (demo.shouldEncrypt) {
		demo.crypto.subtle.encrypt(demo.crypto.keyAlgorithm, key, msgBuffer)
		.then(function(ciphertextData) {
			var ciphertext = base64js.fromByteArray(new Uint8Array(ciphertextData));
			messageObject.message = ciphertext;
			if (demo.shouldSign) {
				demo.crypto.subtle.sign(demo.crypto.keypairAlgorithm, keypair.privateKey, msgBuffer)
				.then(function(signature) {
					var signatureB64enc = base64js.fromByteArray(new Uint8Array(signature));
					messageObject.signature = signatureB64enc;
					sendFn(messageObject)
				}).catch(function(error) {
					console.log(error);
					alertify.error(error);
				});
			} else {
				sendFn(messageObject)
			}

		})
	} else if (demo.shouldSign) {
		demo.crypto.subtle.sign(demo.crypto.keypairAlgorithm, keypair.privateKey, msgBuffer)
		.then(function(signature) {
			var signatureB64enc = base64js.fromByteArray(new Uint8Array(signature));
			messageObject.signature = signatureB64enc;
			sendFn(messageObject)
		}).catch(function(error) {
			console.log(error);
			alertify.error(error);
		})
	} else {
		sendFn(messageObject)
	}
}

demo.handleMessage = function(messageObject) {

	if(demo.doMITM) {
		console.log("Original message: " + messageObject.message);
		messageObject.message = demo.MITM(messageObject.message);
		console.log("Tampered message" + messageObject.message);
	}

	var logMessage = function(msg, valid) {
		demo.out.p2plogIn(msg, valid);
	}

	if (demo.shouldDecrypt) {

		var ciphertextBuffer;

		try {
			ciphertextBuffer = base64js.toByteArray(messageObject.message);
		} catch (e) {
			ciphertextBuffer = new Uint8Array(16);
			alertify.error(e);
		}
		demo.crypto.subtle.decrypt(demo.crypto.keyAlgorithm, demo.decryptionKey, ciphertextBuffer)
		.then(function(decrypted) {
			messageObject.message = String.fromCodePoint.apply(null, new Uint8Array(decrypted));
			if (demo.shouldVerify) {
				demo.verify(messageObject, logMessage);
			} else {
				logMessage(messageObject, null);
			}
		}).catch(function(error) {
			console.log(error);
		 	alertify.error(error);
		 	});
	} else if (demo.shouldVerify) {
		demo.verify(messageObject, logMessage);
	} else {
		logMessage(messageObject, null);
	}
}

demo.verify = function(msg, logMessage) {

	console.log("received for verification", msg);

	if (msg.signature == null) {
		logMessage(msg, false);
		return;
	}

	var msgBuffer = demo.encoder.encode(msg.message);
 	var sigBuffer = base64js.toByteArray(msg.signature);
 	console.log("Signature: " + msg.signature);

	demo.crypto.subtle.verify(demo.crypto.keypairAlgorithm, demo.verificationKey, sigBuffer, msgBuffer)
	.then(function(valid) {
		logMessage(msg,valid);
	}).catch(function(error) {
		console.log(error);
		alertify.error(error);
	});
};

demo.out.serverlog = function(msg) {
	console.log("[serverlog]", msg);
	var old = jQuery("#server-log").val();
	jQuery("#server-log").val(old + msg +"\n");
};
demo.out.p2plog = function(msg) {
	console.log("[p2p-log]", msg);
	jQuery("#p2p-log").append("<p>"+msg+"</p>");
	demo.out.scroll("#p2p-log");
};
demo.out.p2plogIn = function(msg, valid) {
	logMessage = msg.signature != null ?
		msg.message + "<br/><span class='signature'>" +  msg.signature + "</span>" :
		msg.message;
	console.log("[p2p-log] <-", logMessage);

	if (valid != null) {
		var val = (valid) ? "valid" : "invalid";
		jQuery("#p2p-log").append("<p class='in "+val+"'>"+logMessage+"</p>");
	} else {
		jQuery("#p2p-log").append("<p class='in'>"+logMessage+"</p>");
	}
	demo.out.scroll("#p2p-log");
};
demo.out.p2plogOut = function(msg) {
	console.log("[p2p-log] ->", msg);
	jQuery("#p2p-log").append("<p class='out'>"+msg+"</p>");
	demo.out.scroll("#p2p-log");
};
demo.out.scroll = function(e) {
	var h = jQuery(e)[0].scrollHeight;
	jQuery(e).scrollTop(h);
}

demo.init = function() {
	demo.crypto.subtle = window.crypto.subtle;
	var hashAlgorithm = {name: 'SHA-1'};
	demo.crypto.keypairAlgorithm = {
		name: 'RSASSA-PKCS1-v1_5',
		hash: hashAlgorithm,
		modulusLength: 1024,
		publicExponent: new Uint8Array([1,0,1])
	};
        demo.crypto.keyAlgorithm = {
		name: 'AES-CTR',
		counter: new Uint8Array(16),
		length: 128
	};
        demo.encoder = new TextEncoder("utf-8");
	demo.ui_init();
};

demo.ui_init = function() {

	jQuery("#onramp-server").val(demo.server);

	jQuery("#connect-server").click(function() {
		demo.server = jQuery("#onramp-server").val();
    		demo.connect(demo.server);
	});

	jQuery("#clear-server").click(function() {
		jQuery("#server-log").val("");
  	});

	jQuery("#mitm").click(function() {
		if(demo.doMITM) {
			demo.doMITM = false;
			jQuery("#mitm").text("Activate MITM");
			jQuery("#mitm").removeClass("btn-danger");
			alertify.success("MITM has stopped");
		} else {
			demo.doMITM = true;
			jQuery("#mitm").text("Turn-off MITM");
			jQuery("#mitm").addClass("btn-danger");
			alertify.error("MITM is ACTIVE");
		}
	});

	jQuery("#sign").click(function() {
		if(demo.shouldSign) {
			demo.shouldSign = false;
			jQuery("#sign").text("Activate message signing");
			jQuery("#sign").removeClass("btn-danger");
			alertify.success("Message Signing deactivated");
		} else {
			if (demo.keypair != null) {
				demo.shouldSign = true;
				jQuery("#sign").text("Turn-off message signing");
				jQuery("#sign").addClass("btn-danger");
				alertify.success("Message signing is ACTIVE");
			} else {
				alertify.error("Keypair is required for message signing");
			}
		}
	});

	jQuery("#verify").click(function() {
		if(demo.shouldVerify) {
			demo.shouldVerify = false;
			jQuery("#verify").text("Activate signature verification");
			jQuery("#verify").removeClass("btn-danger");
			alertify.success("Signature verification deactivated");
		} else {
			if (demo.verificationKey != null) {
				demo.shouldVerify = true;
				jQuery("#verify").text("Turn-off signature verification");
				jQuery("#verify").addClass("btn-danger");
				alertify.success("Signature verification is ACTIVE");
			} else {
				alertify.error("Verification key is required for signature verification");
			}
		}
	});

	jQuery("#encrypt").click(function() {
		if(demo.shouldEncrypt) {
			demo.shouldEncrypt = false;
			jQuery("#encrypt").text("Activate encryption");
			jQuery("#encrypt").removeClass("btn-danger");
			alertify.success("Encryption deactivated");
		} else {
			if (demo.encryptionKey != null) {
				demo.shouldEncrypt = true;
				jQuery("#encrypt").text("Turn-off encryption");
				jQuery("#encrypt").addClass("btn-danger");
				alertify.success("Encryption is ACTIVE");
			} else {
				alertify.error("Encryption key is required for encryption");
			}
		}
	});

	jQuery("#decrypt").click(function() {
		if(demo.shouldDecrypt) {
			demo.shouldDecrypt = false;
			jQuery("#decrypt").text("Activate decryption");
			jQuery("#decrypt").removeClass("btn-danger");
			alertify.success("Decryption deactivated");
		} else {
			if (demo.decryptionKey != null) {
				demo.shouldDecrypt = true;
				jQuery("#decrypt").text("Turn-off decryption");
				jQuery("#decrypt").addClass("btn-danger");
				alertify.success("Decryption is ACTIVE");
			} else {
				alertify.error("Decryption key is required");
			}
		}
	});

	jQuery("#generateKeypair").click(function() {
		demo.generateKeypair();
	});

        jQuery("#generateEncryptionKey").click(function() {
		demo.generateEncryptionKey();
	});

	jQuery("#clearKeys").click(function() {
		demo.clearKeys();
	        jQuery("#jwk-public-key").text("no key generated");
	        jQuery("#jwk-crypto-key").text("no key generated");
		alertify.success("keys cleared");
	});

	jQuery("#importPublicKey").click(function() {
		var jwk = jQuery("#peer-jwk").val();
		demo.importPublicKey(jwk);
	});
	jQuery("#importDecryptionKey").click(function() {
		var jwk = jQuery("#peer-jwk").val();
		demo.importDecryptionkey(jwk);
	});

	jQuery("#connect-peer").click(function() {
		var to = jQuery("#connect-to").val();
		demo.connectPeer(to);
	});

	jQuery("#send-message").click(function() {
		var msg = jQuery("#message").val();
		demo.sendMessage(msg);
		jQuery("#message").val("");
	});

	jQuery("#change-bg").click(function() {
		var newColor = '#'+(0x1000000+(Math.random())*0xffffff).toString(16).substr(1,6);
		jQuery('body').css('background-color', newColor);
	});

};

jQuery(document).ready(function() {
	demo.init();
});
