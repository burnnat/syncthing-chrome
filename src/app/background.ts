import { CertificateOnlyTlsSocket } from '../lib/cert-socket';

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
