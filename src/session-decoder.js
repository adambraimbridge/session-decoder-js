'use strict';

const crypto = require('crypto');
const base64url = require('base64url');
const msgpack = require('msgpack-javascript');
const long = require('long');

function convertPublicKeyToPEM(publicKey) {
	const base64PublicKey = base64url.toBase64(publicKey);

	return `-----BEGIN PUBLIC KEY-----
${base64PublicKey.replace(/(.{64})/g, '$1')}
-----END PUBLIC KEY-----`;
}

function getSessionFromTokenBuffer(sessionTokenBuffer) {
	const unpacker = new msgpack.Unpacker(sessionTokenBuffer);
	const unpackedLong1 = unpacker.unpackInt();
	const unpackedLong2 = unpacker.unpackInt();

	const mostSignificantBits = new long(unpackedLong1.low, unpackedLong1.high);
	const leastSignificantBits = new long(unpackedLong2.low, unpackedLong2.high);
	return uuidFrom(mostSignificantBits, leastSignificantBits);
}

function uuidFrom(mostSig, leastSig) {
	return [
		toHexDigits(mostSig.shiftRight(32), 8),
		toHexDigits(mostSig.shiftRight(16), 4),
		toHexDigits(mostSig, 4),
		toHexDigits(leastSig.shiftRight(48), 4),
		toHexDigits(leastSig, 12)
	].join('-');
}

function toHexDigits(val, digits) {
	const hi = new long(1).shiftLeft((digits * 4));
	return hi.or((val.and((hi - 1)))).toString(16).substring(1);
}


class SessionDecoder {
	constructor (publicKey) {
		if (!publicKey) {
			throw new Error('missing public key in session token decoder constructor');
		}
		this.publicKey = convertPublicKeyToPEM(publicKey);
	}

	decode (sessionValue) {
		const split = sessionValue.split('.');
		if (split.length !== 2) {
			throw new Error('Invalid session - incorrect format');
		}
		const base64EncodedToken = split[0];
		const base64EncodedSignature = split[1];
		const sessionTokenBuffer = new Buffer(base64EncodedToken, 'base64');
		const verifier = crypto.createVerify('SHA256');

		verifier.update(sessionTokenBuffer);

		const verified = verifier.verify(this.publicKey, base64EncodedSignature, 'base64');
		if (verified) {
			return getSessionFromTokenBuffer(sessionTokenBuffer);
		} else {
			throw new Error('Invalid session - signature verification failed');
		}
	}
}

module.exports = SessionDecoder;
