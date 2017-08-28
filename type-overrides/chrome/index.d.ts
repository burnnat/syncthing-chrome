/// <reference types="chrome/chrome-app" />

declare namespace chrome.sockets.tcp {
	interface SecureOptions {
		tlsVersion?: TlsVersion
	}

	interface TlsVersionSpec {
		min?: TlsVersion;
		max?: TlsVersion;
	}

	type TlsVersion = 'tls1' | 'tls1.1' | 'tls1.2';

	export function secure(socketId: number, callback: (result: number) => void): void;
	export function secure(socketId: number, options: SecureOptions, callback: (result: number) => void): void;
}
