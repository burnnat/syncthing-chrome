// Type definitions for node-forge 0.6.43
// Project: https://github.com/digitalbazaar/forge
// Definitions by: Seth Westphal <https://github.com/westy92>
//                 Kay Schecker <https://github.com/flynetworks>
//                 Aakash Goenka <https://github.com/a-k-g>
//                 Nat Burns <https://github.com/burnnat>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped

declare module "node-forge" {
    type Byte = number;
    type Bytes = string;
    type Hex = string;
    type Base64 = string;
    type Utf8 = string;
    type OID = string;

    namespace pki {

        type PEM = string;
        type Key = any;

        interface KeyPair {
            publicKey: Key;
            privateKey: Key;
        }

        function privateKeyToPem(key: Key, maxline?: number): PEM;
        function publicKeyToPem(key: Key, maxline?: number): PEM;
        function publicKeyFromPem(pem: PEM): Key;
        function privateKeyFromPem(pem: PEM): Key;
        function certificateToPem(cert: Certificate, maxline?: number): PEM;

        interface oids {
            [key: string]: string;
        }
        var oids: oids;

        namespace rsa {

            interface GenerateKeyPairOptions {
                bits?: number;
                e?: number;
                workerScript?: string;
                workers?: number;
                workLoad?: number;
                prng?: any;
                algorithm?: string;
            }

            function generateKeyPair(bits?: number, e?: number, callback?: (err: Error, keypair: KeyPair) => void): KeyPair;
            function generateKeyPair(options?: GenerateKeyPairOptions, callback?: (err: Error, keypair: KeyPair) => void): KeyPair;
        }

        interface CertificateFieldOptions {
            name?: string;
            type?: string;
            shortName?: string;
        }

        interface CertificateField extends CertificateFieldOptions {
            valueConstructed?: boolean;
            valueTagClass?: asn1.Class;
            value?: any[];
            extensions?: any[];
        }

        interface Certificate {
            version: number;
            serialNumber: string;
            signature: any;
            signatureOid: string;
            siginfo: any;
            validity: {
                notBefore: Date;
                notAfter: Date;
            };
            issuer: {
                getField(sn: string | CertificateFieldOptions): any;
                addField(attr: CertificateField): void;
                attributes: any[];
                hash: any;
            };
            subject: {
                getField(sn: string | CertificateFieldOptions): any;
                addField(attr: CertificateField): void;
                attributes: any[];
                hash: any;
            };
            extensions: any[];
            publicKey: any;
            md: any;
        }

        function createCertificate(): Certificate;
        function certificateFromAsn1(obj: asn1.Asn1, computeHash?: boolean): Certificate;

        function decryptRsaPrivateKey(pem: PEM, passphrase?: string): Key;
    }

    namespace ssh {
        /**
         * Encodes a private RSA key as an OpenSSH file.
         */
        function privateKeyToOpenSSH(privateKey?: string, passphrase?: string): string;
    }

    namespace asn1 {
        enum Class {
            UNIVERSAL = 0x00,
            APPLICATION = 0x40,
            CONTEXT_SPECIFIC = 0x80,
            PRIVATE = 0xC0,
        }

        enum Type {
            NONE = 0,
            BOOLEAN = 1,
            INTEGER = 2,
            BITSTRING = 3,
            OCTETSTRING = 4,
            NULL = 5,
            OID = 6,
            ODESC = 7,
            EXTERNAL = 8,
            REAL = 9,
            ENUMERATED = 10,
            EMBEDDED = 11,
            UTF8 = 12,
            ROID = 13,
            SEQUENCE = 16,
            SET = 17,
            PRINTABLESTRING = 19,
            IA5STRING = 22,
            UTCTIME = 23,
            GENERALIZEDTIME = 24,
            BMPSTRING = 30,
        }

        interface Asn1 {
            tagClass: Class;
            type: Type;
            constructed: boolean;
            composed: boolean;
            value: Asn1[];
        }

        interface Asn1Validator {
            name: string;
            tagClass?: Class;
            type?: Type;
            constructed?: boolean;
            optional?: boolean;
            value?: Asn1Validator[];
            capture?: string;
            captureAsn1?: string;
            captureBitStringContents?: string;
            captureBitStringValue?: string;
        }

        function create(tagClass: Class, type: Type, constructed: boolean, value: string | Asn1[]): Asn1;
        function fromDer(bytes: Bytes | util.ByteBuffer, strict?: boolean): Asn1;
        function toDer(obj: Asn1): util.ByteBuffer;
        function oidToDer(oid: OID): util.ByteStringBuffer;
        function derToOid(der: util.ByteStringBuffer): OID;
        function validate(obj: Asn1, validator: Asn1Validator, capture: object, errors: string[]): boolean;
    }

    namespace util {
        function isArray(x: any): boolean;
        function isArrayBuffer(x: any): boolean;
        function isArrayBufferView(x: any): boolean;

        interface ArrayBufferView {
            buffer: ArrayBuffer;
            byteLength: number;
        }

        type ByteBuffer = ByteStringBuffer;
        interface ByteStringBuffer {
            constructor(bytes?: Bytes | ArrayBuffer | ArrayBufferView | ByteStringBuffer);
            data: string;
            read: number;
            length(): number;
            isEmpty(): boolean;
            putByte(byte: Byte): ByteStringBuffer;
            fillWithByte(byte: Byte, n: number): ByteStringBuffer;
            putBytes(bytes: Bytes): ByteStringBuffer;
            putString(str: string): ByteStringBuffer;
            putInt16(int: number): ByteStringBuffer;
            putInt24(int: number): ByteStringBuffer;
            putInt32(int: number): ByteStringBuffer;
            putInt16Le(int: number): ByteStringBuffer;
            putInt24Le(int: number): ByteStringBuffer;
            putInt32Le(int: number): ByteStringBuffer;
            putInt(int: number, numOfBits: number): ByteStringBuffer;
            putSignedInt(int: number, numOfBits: number): ByteStringBuffer;
            putBuffer(buffer: ByteStringBuffer): ByteStringBuffer;
            getByte(): number;
            getInt16(): number;
            getInt24(): number;
            getInt32(): number;
            getInt16Le(): number;
            getInt24Le(): number;
            getInt32Le(): number;
            getInt(numOfBits: number): number;
            getSignedInt(numOfBits: number): number;
            getBytes(count?: number): Bytes;
            bytes(count?: number): Bytes;
            at(index: number): Byte;
            setAt(index: number, byte: number): ByteStringBuffer;
            last(): Byte;
            copy(): ByteStringBuffer;
            compact(): ByteStringBuffer;
            clear(): ByteStringBuffer;
            truncate(): ByteStringBuffer;
            toHex(): Hex;
            toString(): string;
        }

        function fillString(char: string, count: number): string;
        function xorBytes(bytes1: string, bytes2: string, count: number): string;
        function hexToBytes(hex: Hex): Bytes;
        function bytesToHex(bytes: Bytes): Hex;
        function int32ToBytes(int: number): Bytes;
        function encode64(bytes: Bytes, maxline?: number): Base64;
        function decode64(encoded: Base64): Bytes;
        function encodeUtf8(str: string): Utf8;
        function decodeUtf8(encoded: Utf8): string;

        function createBuffer(): ByteBuffer;
        function createBuffer(input: string): ByteBuffer;
        function createBuffer(input: string, encoding: string): ByteBuffer;

        namespace binary {
            namespace raw {
                function encode(x: Uint8Array): Bytes;
                function decode(str: Bytes, output?: Uint8Array, offset?: number): Uint8Array;
            }
            namespace hex {
                function encode(bytes: Bytes | ArrayBuffer | ArrayBufferView | ByteStringBuffer): Hex;
                function decode(hex: Hex, output?: Uint8Array, offset?: number): Uint8Array;
            }
            namespace base64 {
                function encode(input: Uint8Array, maxline?: number): Base64;
                function decode(input: Base64, output?: Uint8Array, offset?: number): Uint8Array;
            }
        }

        namespace text {
            namespace utf8 {
                function encode(str: string, output?: Uint8Array, offset?: number): Uint8Array;
                function decode(bytes: Uint8Array): Utf8;
            }
            namespace utf16 {
                function encode(str: string, output?: Uint8Array, offset?: number): Uint8Array;
                function decode(bytes: Uint8Array): string;
            }
        }
    }

    namespace pkcs12 {

        interface BagsFilter {
            localKeyId?: string;
            localKeyIdHex?: string;
            friendlyName?: string;
            bagType?: string;
        }

        interface Bag {
            type: string;
            attributes: any;
            key?: pki.Key;
            cert?: pki.Certificate;
            asn1: asn1.Asn1
        }

        interface Pkcs12Pfx {
            version: string;
            safeContents: [{
                encrypted: boolean;
                safeBags: Bag[];
            }];
            getBags: (filter: BagsFilter) => {
                [key: string]: Bag[]|undefined;
                localKeyId?: Bag[];
                friendlyName?: Bag[];
            };
            getBagsByFriendlyName: (fiendlyName: string, bagType: string) => Bag[]
            getBagsByLocalKeyId: (localKeyId: string, bagType: string) => Bag[]
        }

        function pkcs12FromAsn1(obj: any, strict?: boolean, password?: string) : Pkcs12Pfx;
        function pkcs12FromAsn1(obj: any, password?: string) : Pkcs12Pfx;
    }

    namespace md {
        interface MessageDigest {
            update(msg: string, encoding?: string): MessageDigest;
            digest(): util.ByteStringBuffer;
        }

        namespace sha1 {
            function create(): MessageDigest;
        }

        namespace sha256 {
            function create(): MessageDigest;
        }

        namespace md5 {
            function create(): MessageDigest;
        }
    }

    namespace tls {
        interface TlsVersion {
            readonly major: number,
            readonly minor: number
        }

        const Versions: {
            TLS_1_0: TlsVersion,
            TLS_1_1: TlsVersion,
            TLS_1_2: TlsVersion
        };

        const SupportedVersions: TlsVersion[];
        const Version: TlsVersion;

        const MaxFragment: number;

        enum ConnectionEnd {
            server,
            client
        }

        enum PRFAlgorithm {
            tls_prf_sha256
        }

        enum BulkCipherAlgorithm {
            null,
            rc4,
            des3,
            aes
        }

        enum CipherType {
            stream,
            block,
            aead
        }

        enum MACAlgorithm {
            none,
            hmac_md5,
            hmac_sha1,
            hmac_sha256,
            hmac_sha384,
            hmac_sha512
        }

        enum CompressionMethod {
            none,
            deflate
        }

        enum ContentType {
            change_cipher_spec,
            alert,
            handshake,
            application_data,
            heartbeat
        }

        enum HandshakeType {
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
            enum Level {
                warning,
                fatal
            }

            enum Description {
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

        enum HeartbeatMessageType {
            heartbeat_request,
            heartbeat_response
        }

        interface SecurityParameters {
            entity: ConnectionEnd,
            prf_algorithm: PRFAlgorithm,
            bulk_cipher_algorithm: BulkCipherAlgorithm,
            cipher_type: CipherType,
            enc_key_length: number,
            block_length: number,
            fixed_iv_length: number,
            record_iv_length: number,
            mac_algorithm: MACAlgorithm,
            mac_length: number,
            mac_key_length: number,
            compression_algorithm: CompressionMethod,
            pre_master_secret: Bytes,
            master_secret: Bytes,
            client_random: Bytes,
            server_random: Bytes
        }

        interface CipherSuite {
            id: number[];
            name: string;
            initSecurityParameters(securityParameters: SecurityParameters): void;
            initConnectionState(state, connection: TlsConnection, securityParameters: SecurityParameters): void;
        }

        const CipherSuites: {
            TLS_RSA_WITH_AES_128_CBC_SHA: CipherSuite;
            TLS_RSA_WITH_AES_256_CBC_SHA: CipherSuite;
        };

        interface CertificateRequest {
            certificate_types: util.ByteBuffer,
            certificate_authorities: util.ByteBuffer
        }

        interface Session {
            id: string;
            version: TlsVersion;
            cipherSuite: CipherSuite;
            compressionMethod: CompressionMethod;
            clientHelloVersion: TlsVersion;
            serverCertificate: pki.Certificate;
            certificateRequest: CertificateRequest;
            clientCertificate: pki.Certificate;
            sp: SecurityParameters;
            md5: md.MessageDigest;
            sha1: md.MessageDigest;
            extensions: {
                server_name: {
                    serverNameList: Bytes[]
                }
            };
            resuming?: boolean;
        }

        interface SessionCache {
            getSession(sessionId: string): Session;
            setSession(sessionId: string, session: Session);
        }

        interface SessionMap {
            [sessionId: string]: Session;
        }

        function createSessionCache(cache: SessionMap, capacity: number): SessionCache;

        interface TlsError {
            message: string;
            send: boolean;
            alert: {
                level: Alert.Level;
                description: Alert.Description;
            }
        }

        interface AllTlsConnectionOptions {
            server: boolean;
            sessionId: string;
            caStore: pki.Certificate[];
            sessionCache: SessionCache;
            cipherSuites: CipherSuite[];
            connected(connection: TlsConnection): void;
            virtualHost: string;
            verifyClient: boolean | 'optional';
            verify(connection: TlsConnection, verified: boolean, depth: number, certs: pki.Certificate[]): boolean;
            getCertificate(connection: TlsConnection, hint: any): pki.Certificate | pki.Certificate[];
            getPrivateKey(connection: TlsConnection, cert: pki.Certificate): pki.Key;
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

            readonly input: util.ByteBuffer;
            readonly tlsData: util.ByteBuffer;
            readonly data: util.ByteBuffer;
            readonly session: Session;

            reset(clearFail: boolean): void;
            handshake(sessionId?: string): void;
            process(data: Bytes): number;
            prepare(data: Bytes): boolean;
            prepareHeartbeatRequest(payload: util.ByteBuffer | Bytes, payloadLength?: number): boolean;
            close(clearFail?: boolean): void;
        }

        function createConnection(options: TlsConnectionOptions): TlsConnection;
    }
}
