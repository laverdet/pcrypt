"use strict";
let shuffle2 = require('./shuffle-2');
let unshuffle = require('./unshuffle');
let unshuffle2 = require('./unshuffle-2');

let shuffle3, unshuffle3;
{
	let twofish = require('twofish/src/twofish').twofish();
	let key = [
		0x4f, 0xeb, 0x1c, 0xa5, 0xf6, 0x1a, 0x67, 0xce,
		0x43, 0xf3, 0xf0, 0x0c, 0xb1, 0x23, 0x88, 0x35,
		0xe9, 0x8b, 0xe8, 0x39, 0xd8, 0x89, 0x8f, 0x5a,
		0x3b, 0x51, 0x2e, 0xa9, 0x47, 0x38, 0xc4, 0x14,
	];
	let fns = [ twofish.encrypt, twofish.decrypt ].map(function(fn) {
		return function(vector) {
			let vector8 = new Uint8Array(vector.buffer, vector.byteOffset, vector.byteLength);
			let output = fn(key, vector8);
			vector8.set(output);
		};
	});
	shuffle3 = fns[0];
	unshuffle3 = fns[1];
}

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
	return byte & 0xf3 | 0x08;
}

function makeIntegrityByte2(byte) {
	return byte & 0xe3 | 0x10;
}

function makeIntegrityByte3() {
	return 0x21;
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
	 * version:  Number; version of encryption.. default is `4`; `2` & `3` are also supported.
	 * returns:  encrypted Buffer
	 */
	encrypt(input, ms, version) {

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
		let shuffleFn = shuffle2;
		let blockSize = 256;
		if (version === 2) {
			output8[totalSize - 1] = makeIntegrityByte1(rand.random());
		} else if (version === 3) {
			output8[totalSize - 1] = makeIntegrityByte2(rand.random());
		} else {
			shuffleFn = shuffle3;
			blockSize = 16;
			output8[totalSize - 1] = makeIntegrityByte3();
		}

		// Encrypt in chunks of 256 bytes
		for (let offset = 4; offset < totalSize - 1; offset += blockSize) {
			for (let ii = 0; ii < blockSize / 4; ++ii) {
				output32[offset / 4 + ii] ^= cipher32[ii];
			}
			shuffleFn(new Int32Array(outputBuffer, offset, blockSize / 4));
			cipher8.set(output8.subarray(offset, offset + blockSize));
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
		let blockSize = 256;
		let unshuffleFn;
		if (version === 1) {
			output8 = new Uint8Array(input.slice(32));
			cipher32 = new Int32Array(cipher8FromIV(input.slice(0, 32)).buffer);
			unshuffleFn = unshuffle;
		} else if (version === 2) {
			output8 = new Uint8Array(input.slice(32, input.length - 1));
			cipher32 = new Int32Array(cipher8FromIV(input.slice(0, 32)).buffer);
			unshuffleFn = unshuffle2;
			// input[input.length - 1] is unchecked integrity byte
		} else {
			output8 = new Uint8Array(input.slice(4, input.length - 1));
			let ms = input.readUInt32BE(0);
			let rand = new Random(ms);
			cipher32 = new Int32Array(cipher8FromRand(rand).buffer);
			if (input[input.length - 1] === 0x21) {
				unshuffleFn = unshuffle3;
				blockSize = 16;
			} else {
				let byte = rand.random();
				unshuffleFn = unshuffle2;
				if (
					input[input.length - 1] !== makeIntegrityByte1(byte) &&
					input[input.length - 1] !== makeIntegrityByte2(byte)
				) {
					throw new Error('Integrity check failed');
				}
			}
		}
		let outputBuffer = output8.buffer;
		let output32 = new Int32Array(outputBuffer);
		
		// Decrypt in chunks of 16 or 256 bytes
		for (let offset = 0; offset < output8.length; offset += blockSize) {
			let tmp = output8.slice(offset, offset + blockSize);
			unshuffleFn(new Int32Array(outputBuffer, offset, blockSize / 4));
			for (let ii = 0; ii < blockSize / 4; ++ii) {
				output32[offset / 4 + ii] ^= cipher32[ii];
			}
			cipher32 = new Int32Array(tmp.buffer);
		}
		return new Buffer(outputBuffer).slice(0, output8.length - output8[output8.length - 1]);
	}
};
