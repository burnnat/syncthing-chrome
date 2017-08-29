import * as forge from 'node-forge';
import { TlsSocket } from '../lib/socket';

const internal = (forge.tls as any).internal;
const handlers = (forge.tls as any).handlers;

enum ECPointFormat {
	uncompressed = 0x00,
	ansiX962_compressed_prime = 0x01,
	ansiX962_compressed_char2 = 0x02
}

enum SupportedGroup {
	sect163k1 = 0x0001,
	sect163r1 = 0x0002,
	sect163r2 = 0x0003,
	sect193r1 = 0x0004,
	sect193r2 = 0x0005,
	sect233k1 = 0x0006,
	sect233r1 = 0x0007,
	sect239k1 = 0x0008,
	sect283k1 = 0x0009,
	sect283r1 = 0x000A,
	sect409k1 = 0x000B,
	sect409r1 = 0x000C,
	sect571k1 = 0x000D,
	sect571r1 = 0x000E,
	secp160k1 = 0x000F,
	secp160r1 = 0x0010,
	secp160r2 = 0x0011,
	secp192k1 = 0x0012,
	secp192r1 = 0x0013,
	secp224k1 = 0x0014,
	secp224r1 = 0x0015,
	secp256k1 = 0x0016,
	secp256r1 = 0x0017,
	secp384r1 = 0x0018,
	secp521r1 = 0x0019,
	brainpoolP256r1 = 0x001A,
	brainpoolP384r1 = 0x001B,
	brainpoolP512r1 = 0x001C,
	x25519 = 0x001D,
	x448 = 0x001E,
	ffdhe2048 = 0x0100,
	ffdhe3072 = 0x0101,
	ffdhe4096 = 0x0102,
	ffdhe6144 = 0x0103,
	ffdhe8192 = 0x0104,
	arbitrary_explicit_prime_curves = 0xFF01,
	arbitrary_explicit_char2_curves = 0xFF02
}

interface ExtendedTlsConnection extends forge.tls.TlsConnection {
	// Modifiable version.
	version: forge.tls.TlsVersion;

	// Supported handshake extensions.
	ecPointFormats: ECPointFormat[];
	supportedGroups: SupportedGroup[];

	// Server certificates.
	certs: forge.util.ByteBuffer[];
}

const readVector = function(b: forge.util.ByteBuffer, lenBytes: number) {
	let len = 0;

	switch (lenBytes) {
	case 1:
		len = b.getByte();
		break;
	case 2:
		len = b.getInt16();
		break;
	case 3:
		len = b.getInt24();
		break;
	case 4:
		len = b.getInt32();
		break;
	}

	return forge.util.createBuffer(b.getBytes(len));
};

const writeVector = function(b: forge.util.ByteBuffer, lenBytes: number, v: forge.util.ByteBuffer) {
	b.putInt(v.length(), lenBytes << 3);
	b.putBuffer(v);
};

internal.createClientHello = function(c: ExtendedTlsConnection) {
	c.session.clientHelloVersion = {
		major: c.version.major,
		minor: c.version.minor
	};

	const cipherSuites = forge.util.createBuffer();

	for (let i = 0; i < c.cipherSuites.length; ++i) {
		const cs = c.cipherSuites[i];
		cipherSuites.putByte(cs.id[0]);
		cipherSuites.putByte(cs.id[1]);
	}

	const cSuites = cipherSuites.length();

	const compressionMethods = forge.util.createBuffer();
	compressionMethods.putByte(forge.tls.CompressionMethod.deflate);
	compressionMethods.putByte(forge.tls.CompressionMethod.none);

	const cMethods = compressionMethods.length();

	const extensions = forge.util.createBuffer();

	if (c.virtualHost) {
		const ext = forge.util.createBuffer();
		ext.putByte(0x00);
		ext.putByte(0x00);

		const serverName = forge.util.createBuffer();
		serverName.putByte(0x00); // type host_name
		writeVector(serverName, 2, forge.util.createBuffer(c.virtualHost));

		const snList = forge.util.createBuffer();
		writeVector(snList, 2, serverName);
		writeVector(ext, 2, snList);

		extensions.putBuffer(ext);
	}

	if (c.ecPointFormats) {
		const ext = forge.util.createBuffer();
		ext.putByte(0x00); // type ec_point_formats
		ext.putByte(0x0b);

		const pointFormats = forge.util.createBuffer();

		const pfList = forge.util.createBuffer();
		for (let i = 0; i < c.ecPointFormats.length; ++i) {
			pfList.putByte(c.ecPointFormats[i]);
		}
		writeVector(pointFormats, 1, pfList);

		writeVector(ext, 2, pointFormats);

		extensions.putBuffer(ext);
	}

	if (c.supportedGroups) {
		const ext = forge.util.createBuffer();
		ext.putByte(0x00); // type supported_groups
		ext.putByte(0x0a);

		const supportedGroups = forge.util.createBuffer();

		const sgList = forge.util.createBuffer();
		for (let i = 0; i < c.supportedGroups.length; ++i) {
			sgList.putInt16(c.supportedGroups[i]);
		}
		writeVector(supportedGroups, 2, sgList);

		writeVector(ext, 2, supportedGroups);

		extensions.putBuffer(ext);
	}

	let extLength = extensions.length();

	if (extLength > 0) {
		extLength += 2;
	}

	const sessionId = c.session.id;

	const length =
		sessionId.length + 1 + // session ID vector
		2 +                    // version (major + minor)
		4 + 28 +               // random time and random bytes
		2 + cSuites +          // cipher suites vector
		1 + cMethods +         // compression methods vector
		extLength;             // extensions vector

	const rval = forge.util.createBuffer();
	rval.putByte(forge.tls.HandshakeType.client_hello);
	rval.putInt24(length);                     // handshake length
	rval.putByte(c.version.major);             // major version
	rval.putByte(c.version.minor);             // minor version
	rval.putBytes(c.session.sp.client_random); // random time + bytes
	writeVector(rval, 1, forge.util.createBuffer(sessionId));
	writeVector(rval, 2, cipherSuites);
	writeVector(rval, 1, compressionMethods);

	if (extLength > 0) {
		writeVector(rval, 2, extensions);
	}

	return rval;
};

class DummyCipher implements forge.tls.CipherSuite {
	id: number[];
	name: string;

	constructor(id: number[], name: string) {
		this.id = id;
		this.name = name;
	}

	initSecurityParameters(securityParameters: forge.tls.SecurityParameters) {}
	initConnectionState(state, connection: forge.tls.TlsConnection, securityParameters: forge.tls.SecurityParameters) {}
}

const originalGetCipherSuite = internal.getCipherSuite;
internal.getCipherSuite = function(twoBytes) {
	const result = originalGetCipherSuite.apply(this, arguments);

	if (result === null) {
		return new DummyCipher([twoBytes.charCodeAt(0), twoBytes.charCodeAt(1)], null)
	}
};

interface Record {
	fragment: forge.util.ByteBuffer;
}

// Custom implementation for handleCertificate
handlers[forge.tls.ConnectionEnd.client][1][11] = function(c: ExtendedTlsConnection, record: Record, length: number) {
	if (length < 3) {
		return c.error(c, {
			message: 'Invalid Certificate message. Message too short.',
			send: true,
			alert: {
				level: forge.tls.Alert.Level.fatal,
				description: forge.tls.Alert.Description.illegal_parameter
			}
		});
	}

	const b = record.fragment;
	const certList = readVector(b, 3);

	c.certs = [];

	while (certList.length() > 0) {
		c.certs.push(readVector(certList, 3));
	}

	c.close();
};

const SYNCTHING_SUITES = [
	new DummyCipher([0xCC, 0xA8], 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305'),
	new DummyCipher([0xCC, 0xA9], 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305'),
	new DummyCipher([0xC0, 0x30], 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'),
	new DummyCipher([0xC0, 0x2C], 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'),
	new DummyCipher([0xC0, 0x2F], 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
	new DummyCipher([0xC0, 0x2B], 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
	new DummyCipher([0xC0, 0x13], 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'),
	new DummyCipher([0xC0, 0x23], 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'),
	new DummyCipher([0xC0, 0x28], 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'),
	new DummyCipher([0xC0, 0x0A], 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'),
];

const SYNCTHING_EC_POINT_FORMATS = [
	ECPointFormat.uncompressed
];

const SYNCTHING_SUPPORTED_GROUPS = [
	SupportedGroup.secp256r1,
	SupportedGroup.secp384r1,
	SupportedGroup.secp521r1,
	SupportedGroup.x25519
];

export class CertificateOnlyTlsSocket extends TlsSocket {
	tls: ExtendedTlsConnection;

	protected initializeTls(options: forge.tls.TlsConnectionOptions) {
		options.cipherSuites = SYNCTHING_SUITES;

		super.initializeTls(options);

		this.tls.version = forge.tls.Versions.TLS_1_2;
		this.tls.ecPointFormats = SYNCTHING_EC_POINT_FORMATS;
		this.tls.supportedGroups = SYNCTHING_SUPPORTED_GROUPS;
	}
}
