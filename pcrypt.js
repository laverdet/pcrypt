"use strict";
let shuffle = require('./shuffle');
let shuffle2 = require('./shuffle-2');
let unshuffle = require('./unshuffle');
let unshuffle2 = require('./unshuffle-2');

function rotl8(val, bits) {
	return ((val << bits) | (val >> (8 - bits))) & 0xff;
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

module.exports = {
	/**
	 * input:    cleartext Buffer
	 * iv:       Buffer; optional; length 32
	 * version:  Number; optional; 1 or 2 - default: 2
	 * returns:  encrypted Buffer
	 *
	 * note: Only partial support is implemented for version 2. There is 1 byte that is unaccounted
	 * for.
	 */
	encrypt(input, iv, version) {

		// Sanity checks
		if (!(input instanceof Buffer)) {
			throw new Error('Input must be Buffer');
		} else if (input.length === 0) {
			throw new Error('Input is empty');
		}
		if (iv) {
			if (!(iv instanceof Buffer)) {
				throw new Error('iv must be Buffer');
			} else if (iv.length !== 32) {
				throw new Error('iv must be 32 bytes');
			}
		}
		if (version === undefined) {
			version = 2;
		} else if (version !== 1 && version !== 2) {
			throw new Error('version must be 1 or 2');
		}

		// Allocate output space
		let roundedSize = input.length + (256 - (input.length % 256));
		let totalSize = roundedSize + 32;
		let extraSize = version > 1 ? 1 : 0;
		let outputBuffer = new ArrayBuffer(totalSize + extraSize);
		let output8 = new Uint8Array(outputBuffer);
		let output32 = new Uint32Array(outputBuffer);

		// Write out IV
		if (!iv) {
			iv = Buffer.allocUnsafe ? Buffer.allocUnsafe(32) : new Buffer(32);
			for (let ii = 0; ii < iv.length; ++ii) {
				iv[ii] = Math.random() * Math.pow(2, 8);
			}
		}
		iv.copy(output8);
		input.copy(output8, 32);
		if (roundedSize > input.length) {
			output8.fill(0, 32 + input.length);
		}
		output8[totalSize - 1] = 256 - (input.length % 256);

		// Initialize cipher
		let cipher8 = cipher8FromIV(iv);
		let cipher32 = new Int32Array(cipher8.buffer);

		// Encrypt in chunks of 256 bytes
		let shuffleFn = version === 1 ? shuffle : shuffle2;
		for (let offset = 32; offset < totalSize; offset += 256) {
			for (let ii = 0; ii < 64; ++ii) {
				output32[offset / 4 + ii] ^= cipher32[ii];
			}
			shuffleFn(new Int32Array(outputBuffer, offset, 64));
			cipher8.set(output8.subarray(offset, offset + 256));
		}

		// TODO: Unclear how final byte is being calculated
		return new Buffer(outputBuffer);
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
		} else if (input.length < 288) {
			throw new Error('Invalid input length');
		} else {
			let modSize = (input.length - 32) % 256;
			if (modSize === 0) {
				version = 1;
			} else if (modSize === 1) {
				version = 2;
			} else {
				throw new Error('Invalid input length');
			}
		}

		// Allocate space for decrypted payload
		let output8;
		if (version === 1) {
			output8 = new Uint8Array(input.slice(32));
		} else {
			output8 = new Uint8Array(input.slice(32, input.length - 1));
		}
		let outputBuffer = output8.buffer;
		let output32 = new Int32Array(outputBuffer);

		// Initialize cipher
		let cipher32 = new Int32Array(cipher8FromIV(input.slice(0, 32)).buffer);
		
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
