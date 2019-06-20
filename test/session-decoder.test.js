const expect = require('chai').expect;
const SessionDecoder = require('../src/session-decoder');
const pubKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4U5p7RQ4YR89NPSuQFoNBaras4BSrBirYO1JzAnfVJr9FfEqpDyHiW1Vwg9RcYp7Uo7E_fE6Pq-3rb9lD6m6wA';
const decoder = new SessionDecoder(pubKey);

describe('The SessionDecoder', () => {
	it('should return a uuid from a valid session', () => {
		const uuid = decoder.decode(
			'z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIw'
		);
		expect(uuid).to.equal('5866ad86-183e-465d-9a45-74bb031b540a');
	});

	it('should throw format error if session format incorrect', () => {
		expect(() => {
			decoder.decode('someInvalidInput');
		}).to.throw('Invalid session - incorrect format');
	});

	it('should throw verification error if session token is modified', () => {
		expect(() => {
			decoder.decode('Z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIw');
		}).to.throw('Invalid session - signature verification failed');
	});

	it('should throw verification error if session signature is modified', () => {
		expect(() => {
			decoder.decode('z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIW');
		}).to.throw('Invalid session - signature verification failed');
	});

	it('should throw PEM read error if public key is bad', () => {
		expect(() => {
			new SessionDecoder('someBadPublicKey')
				.decode('z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIw');
		}).to.throw('error:0D07207B:asn1 encoding routines:ASN1_get_object:header too long');
	});
});
