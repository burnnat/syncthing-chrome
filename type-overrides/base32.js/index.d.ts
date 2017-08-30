declare module 'base32.js' {
	type Variant = 'rfc4648' | 'crockford' | 'base32hex';

	interface CharMap {
		[char: string]: number
	}

	interface DecoderOptions {
		type?: Variant;
		charmap?: CharMap;
	}

	class Decoder {
		charmap: CharMap;

		constructor(options?: DecoderOptions);

		write(str: string): Decoder;
		finalize(str?: string): number[];
	}

	interface EncoderOptions {
		type?: Variant;
		alphabet?: string;
		lc?: boolean;
	}

	class Encoder {
		alphabet: string;

		constructor(options?: EncoderOptions);

		write(buf: number[]): Encoder;
		finalize(buf?: number[]): string;
	}

	function encode(buf: number[], options?: EncoderOptions): string;
	function decode(str: string, options?: DecoderOptions): number[];

	function charmap(alphabet: string, mappings: CharMap): CharMap;

	interface VariantSpec {
		alphabet: string;
		charmap: CharMap;
	}

	const rfc4648: VariantSpec;
	const crockford: VariantSpec;
	const base32hex: VariantSpec;
}
