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

function shuffle4(vector) {
	let xbox = new Uint8Array([
		0x83, 0x57, 0x47, 0x28, 0x1c, 0x84, 0x5c, 0xf0, 0x25, 0xcc, 0x14, 0xd1, 0xe4, 0xe0, 0x4b, 0x4c,
		0x68, 0x20, 0x72, 0x37, 0x34, 0x7b, 0x23, 0xf3, 0x7d, 0x62, 0x8c, 0xa7, 0xe2, 0xa8, 0x88, 0x6e,
		0x27, 0x74, 0x3e, 0x94, 0x2a, 0x6d, 0x3b, 0xa5, 0x7a, 0x41, 0xa3, 0x13, 0x8b, 0x31, 0x42, 0x09,
		0xb4, 0x16, 0x2f, 0xb7, 0x06, 0x04, 0x75, 0x39, 0x67, 0xc0, 0x30, 0xde, 0xa4, 0xf8, 0xd8, 0x19,
		0xf7, 0xf9, 0x2d, 0xae, 0xc2, 0xe9, 0xcb, 0xc1, 0x1b, 0x5e, 0xc3, 0x08, 0xaa, 0x4f, 0xd4, 0xbf,
		0x35, 0x63, 0x2e, 0x8f, 0x9f, 0x0f, 0x8a, 0x97, 0xb8, 0x3a, 0xa6, 0x48, 0x98, 0x11, 0x71, 0x89,
		0x6c, 0x9b, 0x0a, 0x61, 0xa9, 0x86, 0x22, 0xe3, 0x03, 0x7f, 0x4a, 0x99, 0x00, 0xab, 0xed, 0xf2,
		0x9a, 0xba, 0x52, 0x29, 0x1e, 0xbe, 0xfc, 0xa0, 0x65, 0x6a, 0x78, 0xca, 0x69, 0xd0, 0x21, 0x49,
		0xbd, 0x4d, 0x2c, 0x7e, 0x53, 0xb5, 0xe6, 0xdc, 0x60, 0x8e, 0xfd, 0x17, 0x82, 0x0e, 0x9c, 0x4e,
		0xaf, 0xc5, 0xc4, 0x5d, 0x81, 0xf4, 0x02, 0x5b, 0x0b, 0x50, 0xac, 0x45, 0x95, 0x5f, 0x38, 0xd3,
		0x76, 0xc7, 0x07, 0x90, 0x92, 0x79, 0x15, 0x77, 0xdb, 0x12, 0x3d, 0xbc, 0x10, 0x1a, 0x51, 0xb9,
		0x32, 0xbb, 0x26, 0x56, 0xdd, 0xd9, 0xe5, 0x7c, 0xe8, 0xe7, 0xad, 0xd2, 0xf6, 0xee, 0xcf, 0xfe,
		0x87, 0x66, 0x64, 0xf5, 0xcd, 0xe1, 0xc9, 0xfa, 0x0c, 0x01, 0x6b, 0x3f, 0x0d, 0xda, 0x96, 0x40,
		0xa2, 0x1f, 0x5a, 0x24, 0xeb, 0x59, 0xec, 0x44, 0x43, 0x91, 0xb0, 0xb2, 0xd7, 0x54, 0x2b, 0xce,
		0x33, 0xff, 0x58, 0x18, 0x93, 0x46, 0xc8, 0xdf, 0x3c, 0xfb, 0x8d, 0xb1, 0x55, 0xd5, 0x6f, 0x70,
		0xef, 0x9d, 0xa1, 0x9e, 0xb6, 0xea, 0xc6, 0xf1, 0x80, 0x1d, 0x05, 0x73, 0xd6, 0xb3, 0x36, 0x85
	]);

	let v4 = 0;
	let v5 = 0;
	for (let ii = 0; ii < vector.length; ++ii) {
		v4 = (v4 + 1) & 0xff;
		let v7 = xbox[v4];
		v5 = (v5 + v7) & 0xff;
		let v9 = xbox[v5];
		xbox[v4] = v9;
		xbox[v5] = v7;
		vector[ii] ^= xbox[(v7 + v9) & 0xff];
	}
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
	 * version:  Number; version of encryption.. default is 5; 2, 3 & 4 are also supported.
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
		if (version === undefined) {
			version = 5;
		}
		if (version === 2) {
			output8[totalSize - 1] = makeIntegrityByte1(rand.random());
		} else if (version === 3) {
			output8[totalSize - 1] = makeIntegrityByte2(rand.random());
		} else if (version === 4 || version === 5) {
			shuffleFn = shuffle3;
			blockSize = 16;
			output8[totalSize - 1] = 0x21;
		}

		// Encrypt in chunks of 256 bytes
		for (let offset = 4; offset < totalSize - 1; offset += blockSize) {
			for (let ii = 0; ii < blockSize / 4; ++ii) {
				output32[offset / 4 + ii] ^= cipher32[ii];
			}
			shuffleFn(new Int32Array(outputBuffer, offset, blockSize / 4));
			cipher8.set(output8.subarray(offset, offset + blockSize));
		}

		// Extra cipher
		if (version === 5) {
			shuffle4(output8);
			output8[totalSize - 1] = 0x23;
		}

		return new Buffer(outputBuffer).slice(0, totalSize);
	},

	/**
	 * input:    encrypted Buffer
	 * returns:  cleartext Buffer
	 */
	decrypt(input) {

		// Sanity checks
		let version; // This `version` is not the same as `version` in encrypt. Sorry.
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
			let integrityByte = input[input.length - 1];
			if (integrityByte === 0x23) {
				shuffle4(input); // shuffle4 is involutory
				integrityByte = 0x21;
			}
			output8 = new Uint8Array(input.slice(4, input.length - 1));
			let ms = input.readUInt32BE(0);
			let rand = new Random(ms);
			cipher32 = new Int32Array(cipher8FromRand(rand).buffer);
			if (integrityByte === 0x21) {
				unshuffleFn = unshuffle3;
				blockSize = 16;
			} else {
				let byte = rand.random();
				unshuffleFn = unshuffle2;
				if (
					integrityByte !== makeIntegrityByte1(byte) &&
					integrityByte !== makeIntegrityByte2(byte)
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
