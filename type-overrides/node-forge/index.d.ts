declare module 'node-forge' {
	/**
	 * FROM DEFAULT DEFINITIONS
	 */
	interface MessageDigest {
		update(msg: string, encoding?: string): MessageDigest;
		digest(): util.ByteStringBuffer;
	}
	/**
	 * END DEFAULTS
	 */

	namespace tls {
		interface TlsVersion {
			readonly major: number,
			readonly minor: number
		}

		export const Versions: {
			TLS_1_0: TlsVersion,
			TLS_1_1: TlsVersion,
			TLS_1_2: TlsVersion
		};

		export const SupportedVersions: TlsVersion[];
		export const Version: TlsVersion;

		export const MaxFragment: number;

		export enum ConnectionEnd {
			server,
			client
		}

		export enum PRFAlgorithm {
			tls_prf_sha256
		}

		export enum BulkCipherAlgorithm {
			null,
			rc4,
			des3,
			aes
		}

		export enum CipherType {
			stream,
			block,
			aead
		}

		export enum MACAlgorithm {
			none,
			hmac_md5,
			hmac_sha1,
			hmac_sha256,
			hmac_sha384,
			hmac_sha512
		}

		export enum CompressionMethod {
			none,
			deflate
		}

		export enum ContentType {
			change_cipher_spec,
			alert,
			handshake,
			application_data,
			heartbeat
		}

		export enum HandshakeType {
			hello_request,
			client_hello,
			server_hello,
			certificate,
			server_key_exchange,
			certificate_request,
			server_hello_done,
			certificate_verify,
			client_key_exchange,
			finished
		}

		namespace Alert {
			export enum Level {
				warning,
				fatal
			}

			export enum Description {
				close_notify,
				unexpected_message,
				bad_record_mac,
				decryption_failed,
				record_overflow,
				decompression_failure,
				handshake_failure,
				bad_certificate,
				unsupported_certificate,
				certificate_revoked,
				certificate_expired,
				certificate_unknown,
				illegal_parameter,
				unknown_ca,
				access_denied,
				decode_error,
				decrypt_error,
				export_restriction,
				protocol_version,
				insufficient_security,
				internal_error,
				user_canceled,
				no_renegotiation
			}
		}

		export enum HeartbeatMessageType {
			heartbeat_request,
			heartbeat_response
		}

		type SecurityParameters = object;

		interface CipherSuite {
			id: number[];
			name: string;
			initSecurityParameters(securityParameters: SecurityParameters): void;
			initConnectionState(state, connection: TlsConnection, securityParameters: SecurityParameters): void;
		}

		export const CipherSuites: {
			TLS_RSA_WITH_AES_128_CBC_SHA: CipherSuite;
			TLS_RSA_WITH_AES_256_CBC_SHA: CipherSuite;
		};

		interface Certificate {}

		interface CertificateRequest {
			certificate_types: Bytes,
			certificate_authorities: Bytes
		}

		interface Session {
			id: string,
			version: TlsVersion,
			cipherSuite: CipherSuite,
			compressionMethod: CompressionMethod,
			serverCertificate: Certificate,
			certificateRequest: CertificateRequest,
			clientCertificate: Certificate,
			sp: SecurityParameters,
			md5: MessageDigest,
			sha1: MessageDigest
		}

		interface SessionCache {
			getSession(sessionId: string): Session;
			setSession(sessionId: string, session: Session);
		}

		interface SessionMap {
			[sessionId: string]: Session;
		}

		export function createSessionCache(cache: SessionMap, capacity: number): SessionCache;

		type Key = any;
		type Bytes = any;

		interface TlsError {
			message: string,
			send: boolean,
			alert: {
				level: Alert.Level,
				description: Alert.Description
			}
		}

		interface AllTlsConnectionOptions {
			server: boolean;
			sessionId: string;
			caStore: Certificate[];
			sessionCache: SessionCache;
			cipherSuites: CipherSuite[];
			connected(connection: TlsConnection): void;
			virtualHost: string;
			verifyClient: boolean | 'optional';
			verify(connection: TlsConnection, verified: boolean, depth: number, certs: Certificate[]): boolean;
			getCertificate(connection: TlsConnection, hint: any): Certificate | Certificate[];
			getPrivateKey(connection: TlsConnection, cert: Certificate): Key;
			getSignature(connection: TlsConnection, bytes: Bytes, callback: (connection: TlsConnection, bytes: Bytes) => void): void;
			tlsDataReady(connection: TlsConnection): void;
			dataReady(connection: TlsConnection): void;
			closed(connection: TlsConnection): void;
			error(connection: TlsConnection, error: TlsError): void;
			deflate(bytes: Bytes): Bytes;
			inflate(bytes: Bytes): Bytes;
		}

		type TlsConnectionOptions = Partial<AllTlsConnectionOptions>;

		interface TlsConnection extends Readonly<AllTlsConnectionOptions> {
			readonly entity: ConnectionEnd;
			readonly version: TlsVersion;
			readonly open: boolean;

			readonly input: Bytes;
			readonly tlsData: util.ByteBuffer;
			readonly data: util.ByteBuffer;

			reset(clearFail: boolean): void;
			handshake(sessionId?: string): void;
			process(data: string): number;
			prepare(data: string): boolean;
			prepareHeartbeatRequest(payload: string | Bytes, payloadLength?: number): boolean;
			close(clearFail?: boolean): void;
		}

		export function createConnection(options: TlsConnectionOptions): TlsConnection;
	}
}
