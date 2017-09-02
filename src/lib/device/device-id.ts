import * as forge from 'node-forge';
import * as base32 from 'base32.js';

import { DeviceId } from 'common/types';
import * as luhn from './luhn';

export function parseDeviceId(der: forge.util.ByteBuffer): DeviceId {
	const md = forge.md.sha256.create();

	md.update(der.bytes());

	const buffer = md.digest();
	const bytes: number[] = [];

	while (buffer.length() > 0) {
		bytes.push(buffer.getByte());
	}

	let remaining = base32.encode(bytes);
	let result = '';

	while (remaining.length > 0) {
		let group = remaining.substring(0, 13);
		remaining = remaining.substring(13);

		group += luhn.generate(group);

		if (result.length > 0) {
			result += '-';
		}

		result += group.substring(0, 7) + '-' + group.substring(7);
	}

	return result;
}
