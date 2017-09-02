import { DeviceId, DeviceCertificate } from './types';

export enum ActionType {
	CONNECT='CONNECT',
	FETCH_CERT='FETCH_CERT',
	REGISTER_DEVICE='REGISTER_DEVICE',
	ERROR='ERROR'
}

export interface Action {
	type: ActionType
}

export interface FetchCertAction extends Action {
	type: ActionType.FETCH_CERT,
	host: string,
	port: number
}

export interface RegisterDeviceAction extends Action {
	type: ActionType.REGISTER_DEVICE,
	id: DeviceId,
	cert: DeviceCertificate
}

export interface ConnectAction extends Action {
	type: ActionType.CONNECT,
	host: string,
	port: number
}

export interface ErrorAction extends Action {
	type: ActionType.ERROR,
	message: string
}

export type SyncthingAction = FetchCertAction | ConnectAction | RegisterDeviceAction | ErrorAction;
