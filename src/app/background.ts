import tls from 'node-forge/lib/tls';
import { TlsSocket } from '../lib/socket';

class DummyCipher implements tls.CipherSuite {
	id: number[];
	name: string;

	constructor(id: number[], name: string) {
		this.id = id;
		this.name = name;
	}

	initSecurityParameters(securityParameters: tls.SecurityParameters) {}
	initConnectionState(state, connection: tls.TlsConnection, securityParameters: tls.SecurityParameters) {}
}

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

class CertificateOnlyTlsSocket extends TlsSocket {
	protected initializeTls(options: tls.TlsConnectionOptions) {
		options.cipherSuites = SYNCTHING_SUITES;

		super.initializeTls(options);

		(this.tls.version as any) = tls.Versions.TLS_1_2;
	}

	protected verify(connection: tls.TlsConnection, verified: boolean, depth: number, certs: tls.Certificate[]) {
		this.log('Verifying...');
		return true;
	}
}

chrome.app.runtime.onLaunched.addListener(() => {
	const socket = new CertificateOnlyTlsSocket();

	socket.connect('192.168.1.200', 22000);

	// chrome.sockets.tcp.create(
	// 	{ name: 'syncthing' },
	// 	(createInfo) => {
	// 		const id = createInfo.socketId;

	// 		chrome.sockets.tcp.setPaused(id, true, () => {
	// 			chrome.sockets.tcp.connect(
	// 				id, '192.168.1.200', 22000,
	// 				(connectResult) => {
	// 					console.log(`Connection completed with result: ${connectResult}`);

	// 					chrome.sockets.tcp.secure(id, {}, (secureResult) => {
	// 						console.log(`TLS initialized with result: ${secureResult}`);

	// 						chrome.sockets.tcp.setPaused(id, false, () => {
	// 							console.log('Connection ready!')
	// 						});
	// 					});
	// 				}
	// 			);
	// 		});
	// 	}
	// );

	// chrome.app.window.create('window.html', {
	// 	outerBounds: {
	// 		width: 400,
	// 		height: 500
	// 	}
	// });
});
