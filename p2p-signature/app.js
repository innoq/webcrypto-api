// Small Webcrypto API demo by sending signed messages via websockets
// (see http://www.w3.org/TR/WebCryptoAPI/)
//
// A browser with decent webRTC and ecma script 6 support is needed, for example firefox or chrome
//
// snippet by: innoq.com, simon.koelsch

var demo = demo || {};

demo.keypair = {};
demo.crypto = {};
demo.out = {};

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

demo.generateKey = function() {

	console.log("generating keypair for algorithm: ", demo.crypto.algorithm);

	var extractable = true;
	var usages = ['sign', 'verify'];

	demo.crypto.subtle.generateKey(demo.crypto.algorithm, extractable, usages)
	.then(function(keypair) {
		demo.storeKey(keypair);
		console.log("keypair generated");
		alertify.success("keypair generated");
	}).catch(function(error) {
		console.log(error); alertify.error(error);});
};

demo.storeKey = function (keypair) {

	demo.keypair = keypair;
  	demo.crypto.subtle.exportKey('jwk',keypair.publicKey)
  	.then(function(key) {
			jQuery("#jwk-public-key").text(JSON.stringify(key));
  	}).catch(function (error) {console.log(error); alertify.error(error);});
};

demo.clearKey = function () {
	demo.keypair = {};
}

demo.doMITM = false;
demo.MITM = function(message) {
	return message.replace(/\w*/g, "hodor ");
};

demo.importKey = function(jwkJson) {
	
	try {
		var jwk = JSON.parse(jwkJson);

		console.log("JSON parsed for JWK import");
	
		var extractable = true;
		var usages = ['verify'];

		demo.crypto.subtle.importKey("jwk", jwk, demo.crypto.algorithm, extractable, usages)
		.then(function(keyImport) {
			demo.verificationKey = keyImport;
			console.log("key imported");
			alertify.success("key imported");
		}).catch(function(error) {
			console.log(error); alertify.error(error);});

	} catch(error) {
		console.log(error); alertify.error(error);}
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
	console.log("[p2p-log] <-", msg);

	if (valid != null) { 
		var val = (valid) ? "valid" : "invalid";
		jQuery("#p2p-log").append("<p class='in "+val+"'>"+msg+"</p>");
	} else {
		jQuery("#p2p-log").append("<p class='in'>"+msg+"</p>");
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

demo.sendMessage = function(msg) {

	var send = function(messageObject) {
		demo.peer.send(messageObject);
		demo.out.p2plogOut(msg);
	}
	
	demo.createMessage(msg, demo.keypair.privateKey, send);
};
	
demo.createMessage = function(msg, key, send) {
	
	var messageObject = {'message' : msg, 'signature' : false};
	if (demo.keypair.privateKey != null) {

		demo.crypto.subtle.sign(demo.crypto.algorithm, key, demo.encoder.encode(msg))
		.then(function(signature) {

			var sig = new Uint8Array(signature);
			messageObject.signature = sig;
			send(messageObject);

		}).catch(function(error) {
			console.log(error); alertify.error(error);});

	} else {
		send(messageObject);
	}
};

demo.handleMessage = function(messageObject) { 

	if(demo.doMITM) {
		messageObject.message = demo.MITM(messageObject.message);
	}

	var output = function(msg, valid) {
		demo.out.p2plogIn(messageObject.message, valid);
	}

	if (messageObject.signature != false) {
		demo.verify(messageObject, "TODO", output);
	} else {
		output(messageObject.message, null);
	}
}

demo.verify = function(msg, peerId, output) {
	
	console.log("received for verification", msg);

	var msgBuffer = demo.encoder.encode(msg.message);
	var sigBuffer = demo.toTypedArray(msg.signature).buffer;

	demo.crypto.subtle.verify(demo.crypto.algorithm, demo.verificationKey, sigBuffer, msgBuffer)
	.then(function(valid) {
		output(msg,valid);
	}).catch(function(error) {
		console.log(error); alertify.error(error);});
};

demo.init = function() {
	demo.crypto.subtle = window.crypto.subtle;
	var hashAlgorithm = {name: 'SHA-1'};
	demo.crypto.algorithm = {name: 'RSASSA-PKCS1-v1_5', 
									hash: hashAlgorithm, 
									modulusLength: 1024, 
									publicExponent: new Uint8Array([1,0,1])};
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
			jQuery("#mitm").text("Activate MITM on this client");
			jQuery("#mitm").removeClass("btn-danger");
			alertify.success("MITM has stopped");
		} else {
			demo.doMITM = true;
			jQuery("#mitm").text("Turn-off MITM on this client");
			jQuery("#mitm").addClass("btn-danger");
			alertify.error("MITM is ACTIVE");
		}
	});

	jQuery("#generateKey").click(function() {
		demo.generateKey();
	});
	
	jQuery("#clearKey").click(function() {
		demo.clearKey();
		jQuery("#jwk-public-key").text("no key generated");
		alertify.success("key cleared");
	});
	
	jQuery("#importKey").click(function() {
		var jwk = jQuery("#peer-jwk").val();
		demo.importKey(jwk);
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

// ugly array conversion hack with jquery
demo.toTypedArray = function(obj) {
	var array = $.map(obj, function(value, index) {
    return [value];
	});

	return new Uint8Array(array);
}

jQuery(document).ready(function() {
	demo.init();
});
