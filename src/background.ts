import * as forge from 'node-forge';

import { fetchCertificate } from './lib/cert-socket';
import { parseDeviceId } from './lib/device-id';

chrome.app.runtime.onLaunched.addListener(() => {
	fetchCertificate('192.168.1.200', 22000)
		.then(
			(cert) => {
				console.log(
					'Certificate PEM:\n' +
					'-----BEGIN CERTIFICATE-----\n' +
					forge.util.encode64(cert.bytes()) + '\n' +
					'-----END CERTIFICATE-----'
				);

				console.log('Device ID: ' + parseDeviceId(cert));
			},
			(error) => {
				console.error(error);
			}
		);

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

	chrome.app.window.create('app.html', {
		outerBounds: {
			width: 600,
			height: 500
		}
	});
});
