const crypto = require("crypto")
    , base64url = require('base64url')
    , msgpack = require('msgpack-javascript')
    , long = require("long");

function SessionDecoder(publicKey) {
    this.publicKey = convertPublicKeyToPEM(publicKey);

    function convertPublicKeyToPEM(publicKey) {
        const base64PublicKey = base64url.toBase64(publicKey);
        const beginString = '-----BEGIN PUBLIC KEY-----\n';
        const endString = '\n-----END PUBLIC KEY-----';
        return beginString + base64PublicKey.replace(/(.{64})/g, "$1") + endString;
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
        return toHexDigits(mostSig.shiftRight(32), 8)  + "-" +
               toHexDigits(mostSig.shiftRight(16), 4)  + "-" +
               toHexDigits(mostSig, 4)                 + "-" +
               toHexDigits(leastSig.shiftRight(48), 4) + "-" +
               toHexDigits(leastSig, 12);
    }

    function toHexDigits(val, digits) {
        const hi = new long(1).shiftLeft((digits * 4));
        return hi.or((val.and((hi - 1)))).toString(16).substring(1);
    }

    this.decode = (sessionValue) => {
        const split = sessionValue.split(".");
        if (split.length !== 2) {
            throw "Invalid session - incorrect format"
        }
        const base64EncodedToken = split[0];
        const base64EncodedSignature = split[1];
        const sessionTokenBuffer = Buffer.from(base64EncodedToken, 'base64');
        const verifier = crypto.createVerify('SHA256');

        verifier.update(sessionTokenBuffer);

        const verified = verifier.verify(this.publicKey, base64EncodedSignature, 'base64');
        if (verified) {
            return getSessionFromTokenBuffer(sessionTokenBuffer);
        } else {
            throw "Invalid session - signature verification failed";
        }
    }
}
module.exports = SessionDecoder;