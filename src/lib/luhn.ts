import * as base32 from 'base32.js';

const alphabet = base32.rfc4648.alphabet;

export function generate(input: string): string {
	let factor = 1;
	let sum = 0;
	let n = alphabet.length;

	for (let i = 0; i < input.length; i++) {
		let codepoint = alphabet.indexOf(input.charAt(i));

		if (codepoint < 0) {
			throw new Error(`Digit ${input.charAt(i)} is not valid in alphabet ${alphabet}`);
		}

		let addend = factor * codepoint;
		addend = Math.floor(addend / n) + (addend % n);
		sum += addend;

		factor = factor === 2 ? 1 : 2;
	}

	let remainder = sum % n;
	let checkCodepoint = (n - remainder) % n;

	return alphabet.charAt(checkCodepoint);
}

export function validate(input: string): boolean {
	let last = input.length - 1;
	let data = input.substring(0, last);
	let check = input.substring(last);

	return check === generate(data);
}
