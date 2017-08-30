import * as forge from 'node-forge';

const toArrayBuffer = (buffer: forge.util.ByteStringBuffer): ArrayBuffer => {
	const bytes = buffer.getBytes();
	let data = new Uint8Array(bytes.length);

	for (let i = 0; i < bytes.length; ++i) {
		data[i] = bytes.charCodeAt(i);
	}

	return data.buffer;
};

const toByteString = (buffer: ArrayBuffer): string => String.fromCharCode.apply(null, Array.prototype.slice.apply(new Uint8Array(buffer)));

interface SocketListeners {
	onClose?();
}

export class TlsSocket {
	socketId: number;
	tls: forge.tls.TlsConnection;
	listeners: SocketListeners;

	constructor(listeners?: SocketListeners) {
		this.socketId = null;
		this.tls = null;
		this.listeners = listeners;

		// Chrome callbacks
		this.onConnect = this.onConnect.bind(this);
		this.onReceive = this.onReceive.bind(this);
		this.onReceiveError = this.onReceiveError.bind(this);

		// Forge callbacks
		this.verify = this.verify.bind(this);
		this.connected = this.connected.bind(this);
		this.tlsDataReady = this.tlsDataReady.bind(this);
		this.dataReady = this.dataReady.bind(this);
		this.closed = this.closed.bind(this);
		this.error = this.error.bind(this);
	}

	private active() {
		// reset timeout ...
	}

	connect(host: string, port: number) {
		this.active();

		this.log(`Connecting to host ${host} on port ${port}`);

		chrome.sockets.tcp.create((info) => {
			const id = this.socketId = info.socketId;

			if (id > 0) {
				this.log(`Opened socket with ID: ${id}`);

				chrome.sockets.tcp.setPaused(id, true);
				chrome.sockets.tcp.connect(id, host, port, this.onConnect);
			}
			else {
				this.emitError('Unable to create socket');
			}
		});
	}

	private onConnect(status: number) {
		if (status < 0) {
			this.emitChromeError('Unable to connect to socket', status);
			return;
		}

		this.log('Connection succeeded');
		this.initializeTls({
			verify: this.verify,
			connected: this.connected,
			tlsDataReady: this.tlsDataReady,
			dataReady: this.dataReady,
			closed: this.closed,
			error: this.error
		});

		this.log('Starting TLS handshake');
		this.tls.handshake();

		chrome.sockets.tcp.onReceive.addListener(this.onReceive);
		chrome.sockets.tcp.onReceiveError.addListener(this.onReceiveError);
		chrome.sockets.tcp.setPaused(this.socketId, false);
	}

	private emitChromeError(message: any, code: number) {
		let chromeMessage: string;

		if (chrome.runtime.lastError != null) {
			chromeMessage = chrome.runtime.lastError.message;
		}

		this.emitError(`${message}: ${chromeMessage} (error ${-code})`);
	}

	protected emitError(message) {
		console.error(`Error: ${message}`);
	}

	protected log(message) {
		console.log(
			this.socketId !== null
				? `[${this.socketId}] ${message}`
				: message
		);
	}

	protected initializeTls(options: forge.tls.TlsConnectionOptions) {
		this.log('Initializing TLS connection');

		this.tls = forge.tls.createConnection(options);
	}

	close() {
		if (this.tls != null) {
			this.log('Closing TLS connection');
			this.tls.close();
		}
	}

	private closeInternal() {
		if (this.socketId != null) {
			chrome.sockets.tcp.onReceive.removeListener(this.onReceive);
			chrome.sockets.tcp.onReceiveError.removeListener(this.onReceiveError);

			chrome.sockets.tcp.disconnect(this.socketId);
			chrome.sockets.tcp.close(this.socketId);

			this.socketId = null;
		}
	}

	write(buffer: ArrayBuffer) {
		this.tls.prepare(toByteString(buffer));
	}

	private onReceive(info: chrome.sockets.tcp.ReceiveEventArgs) {
		if (info.socketId != this.socketId) {
			return;
		}

		this.active();

		if (!this.tls.open) {
			this.emitError('Received data but TLS connection is no longer open');
			return;
		}

		const buffer = info.data;
		this.log(`Received ${buffer.byteLength} bytes of data`);

		const remaining = this.tls.process(toByteString(buffer));

		if (remaining > 0) {
			this.log(`Anticipating ${remaining} more bytes`);
		}
	}

	private onReceiveError(info: chrome.sockets.tcp.ReceiveErrorEventArgs) {
		if (info.socketId != this.socketId) {
			return;
		}

		this.active();

		if (info.resultCode == -100) {
			this.log('Connection terminated by server');
		}
		else {
			this.emitChromeError('Read from socket', info.resultCode);
		}

		this.closeInternal();
	}

	protected verify(connection: forge.tls.TlsConnection, verified: boolean, depth: number, certs: forge.pki.Certificate[]) {
		return true;
	}

	protected connected(connection: forge.tls.TlsConnection) {
		this.log('Handshake successful');
	}

	private tlsDataReady(connection: forge.tls.TlsConnection) {
		const bytes = connection.tlsData;
		const total = bytes.length();

		if (this.socketId === null || total === 0) {
			return;
		}

		this.log(`Sending ${total} bytes of data`);

		chrome.sockets.tcp.send(
			this.socketId,
			toArrayBuffer(bytes),
			(info) => {
				const resultCode = info.resultCode;

				if (resultCode < 0) {
					this.emitChromeError('Socket error on write', resultCode);
				}

				const sent = info.bytesSent;

				if (sent === total) {
					this.log('Send complete');
				}
				else {
					if (sent > 0) {
						this.emitError(`Incomplete write: wrote ${sent} of ${total} bytes`);
					}

					this.emitError(`Invalid write on socket: code ${resultCode}`);
				}
			}
		);
	}

	private dataReady(connection: forge.tls.TlsConnection) {
		this.log(`Parsed ${connection.data.length()} bytes of data`);
	}

	protected closed(connection: forge.tls.TlsConnection) {
		if (this.listeners.onClose) {
			this.listeners.onClose();
		}

		this.log('TLS connection closed');
		this.closeInternal();
	}

	protected error(connection: forge.tls.TlsConnection, error: forge.tls.TlsError) {
		this.emitError(`TLS error: ${error.message}`);
		this.closeInternal();
	}
}
