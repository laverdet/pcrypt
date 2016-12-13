"use strict";
let shuffle2 = require('./shuffle-2');
let unshuffle = require('./unshuffle');
let unshuffle2 = require('./unshuffle-2');

function rotl8(val, bits) {
	return ((val << bits) | (val >> (8 - bits))) & 0xff;
}

// These simulate arithmetic of uint32_t w/ predictable overflow behavior. If you find yourself
// porting this code to another platform, just use unsigned 32-bit integers and replace the calls
// to these fucntions with + and *
function add32(a, b) {
	return ((a + b) & ~0) >>> 0;
}

function mult32(a, b) {
	function lo(val) {
		return 0xffff & val;
	}

	function hi(val) {
		return (val >> 16) & 0xffff;
	}

	let tmp = lo(a) * lo(b);
	let w0 = lo(tmp);
	let w1 = lo(lo(hi(a) * lo(b) + hi(tmp)) + lo(a) * hi(b));
	return ((w1 << 16) | w0) >>> 0;
}

function cipher8FromIV(iv) {
	let cipher8 = new Uint8Array(256);
	for (let ii = 0; ii < 8; ++ii) {
		for (let jj = 0; jj < 32; ++jj) {
			cipher8[32 * ii + jj] = rotl8(iv[jj], ii);
		}
	}
	return cipher8;
}

function cipher8FromRand(rand) {
	let cipher8 = new Uint8Array(256);
	for (let ii = 0; ii < 256; ++ii) {
		cipher8[ii] = rand.random();
	}
	return cipher8;
}

function makeIntegrityByte1(byte) {
	return byte & 0xe3 | 0x08;
}

function makeIntegrityByte2(byte) {
	return byte & 0xe3 | 0x10;
}

class Random {
	constructor(seed) {
		this.state = seed;
	}

	random() {
		this.state = add32(mult32(0x41c64e6d, this.state), 12345);
		return (this.state >> 16) & 0xff;
	}
}

module.exports = {
	/**
	 * input:    cleartext Buffer
	 * ms:       Number; optional; seed for IV
	 * returns:  encrypted Buffer
	 *
	 * note: This is "version 3". Encryption of previous versions is no longer supported.
	 */
	encrypt(input, ms) {

		// Sanity checks
		if (!(input instanceof Buffer)) {
			throw new Error('Input must be Buffer');
		} else if (input.length === 0) {
			throw new Error('Input is empty');
		}
		if (ms === undefined) {
			ms = Math.floor(Math.random() * 0xffffffff);
		}

		// Allocate output space
		let roundedSize = input.length + (256 - (input.length % 256));
		let totalSize = roundedSize + 5;
		let outputBuffer = new ArrayBuffer(totalSize + 3);
		let output8 = new Uint8Array(outputBuffer);
		let output32 = new Uint32Array(outputBuffer);

		// Write out seed
		let tmp = Buffer.allocUnsafe ? Buffer.allocUnsafe(4) : new Buffer(4);
		tmp.writeUInt32BE(ms, 0);
		tmp.copy(output8);
		input.copy(output8, 4);

		// Fill zeros + mark length
		if (roundedSize > input.length) {
			output8.fill(0, 4 + input.length);
		}
		output8[totalSize - 2] = 256 - (input.length % 256);

		// Generate cipher and integrity byte
		let rand = new Random(ms);
		let cipher8 = cipher8FromRand(rand);
		let cipher32 = new Int32Array(cipher8.buffer);
		output8[totalSize - 1] = makeIntegrityByte2(rand.random());

		// Encrypt in chunks of 256 bytes
		for (let offset = 4; offset < totalSize - 1; offset += 256) {
			for (let ii = 0; ii < 64; ++ii) {
				output32[offset / 4 + ii] ^= cipher32[ii];
			}
			shuffle2(new Int32Array(outputBuffer, offset, 64));
			cipher8.set(output8.subarray(offset, offset + 256));
		}

		return new Buffer(outputBuffer).slice(0, totalSize);
	},

	/**
	 * input:    encrypted Buffer
	 * returns:  cleartext Buffer
	 */
	decrypt(input) {

		// Sanity checks
		let version;
		if (!(input instanceof Buffer)) {
			throw new Error('Input must be Buffer');
		} else if (input.length < 261) {
			throw new Error('Invalid input length');
		} else {
			let modSize = input.length % 256;
			if (modSize === 32) {
				version = 1;
			} else if (modSize === 33) {
				version = 2;
			} else if (modSize === 5) {
				version = 3;
			} else {
				throw new Error('Invalid input length');
			}
		}

		// Get cipher and encrypted blocks
		let output8, cipher32;
		if (version === 1) {
			output8 = new Uint8Array(input.slice(32));
			cipher32 = new Int32Array(cipher8FromIV(input.slice(0, 32)).buffer);
		} else if (version === 2) {
			output8 = new Uint8Array(input.slice(32, input.length - 1));
			cipher32 = new Int32Array(cipher8FromIV(input.slice(0, 32)).buffer);
			// input[input.length - 1] is unchecked integrity byte
		} else {
			output8 = new Uint8Array(input.slice(4, input.length - 1));
			let ms = input.readUInt32BE(0);
			let rand = new Random(ms);
			cipher32 = new Int32Array(cipher8FromRand(rand).buffer);
			let byte = rand.random();
			if (
				input[input.length - 1] !== makeIntegrityByte1(byte) &&
				input[input.length - 1] !== makeIntegrityByte2(byte)
			) {
				throw new Error('Integrity check failed');
			}
		}
		let outputBuffer = output8.buffer;
		let output32 = new Int32Array(outputBuffer);
		
		// Decrypt in chunks of 256 bytes
		let unshuffleFn = version === 1 ? unshuffle : unshuffle2;
		for (let offset = 0; offset < output8.length; offset += 256) {
			let tmp = output8.slice(offset, offset + 256);
			unshuffleFn(new Int32Array(outputBuffer, offset, 64));
			for (let ii = 0; ii < 64; ++ii) {
				output32[offset / 4 + ii] ^= cipher32[ii];
			}
			cipher32 = new Int32Array(tmp.buffer);
		}
		return new Buffer(outputBuffer).slice(0, output8.length - output8[output8.length - 1]);
	}
};
