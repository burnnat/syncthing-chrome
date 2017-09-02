import { ActionType, ConnectAction, FetchCertAction, RegisterDeviceAction, ErrorAction } from './action-type';
import { DeviceId, DeviceCertificate } from './types';

export const connect = (host: string, port: number): ConnectAction => ({
	type: ActionType.CONNECT,
	host,
	port
});

export const fetchCert = (host: string, port: number): FetchCertAction => ({
	type: ActionType.FETCH_CERT,
	host,
	port
});

export const registerDevice = (id: DeviceId, cert: DeviceCertificate): RegisterDeviceAction => ({
	type: ActionType.REGISTER_DEVICE,
	id,
	cert
});

export const error = (message: string): ErrorAction => ({
	type: ActionType.ERROR,
	message
});
