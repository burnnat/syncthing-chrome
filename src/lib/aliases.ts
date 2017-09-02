import { keyBy } from 'lodash';
import * as forge from 'node-forge';
import { Dispatch } from 'redux';
import { ThunkAction } from 'redux-thunk';
import { AliasMap } from 'react-chrome-redux';

import { ActionType, SyncthingAction, FetchCertAction, ConnectAction, ErrorAction } from 'common/action-type';
import { registerDevice, error } from 'common/actions';
import { State } from 'common/state';

import { fetchCertificate } from './tls/cert-socket';
import { parseDeviceId } from './device/device-id';

const handleFetchCert = (action: FetchCertAction) => (dispatch: Dispatch<State>) => {
	fetchCertificate(action.host, action.port)
		.then(
			(cert) => {
				dispatch(
					registerDevice(
						parseDeviceId(cert),
						'-----BEGIN CERTIFICATE-----\n' +
						forge.util.encode64(cert.bytes()) + '\n' +
						'-----END CERTIFICATE-----'
					)
				);
			},
			(message) => {
				dispatch(error(message));
			}
		);
};

const handleConnect = (action: ConnectAction) => (dispatch: Dispatch<State>) => {
	chrome.sockets.tcp.create(
		{ name: 'syncthing' },
		(createInfo) => {
			const id = createInfo.socketId;

			chrome.sockets.tcp.setPaused(id, true, () => {
				chrome.sockets.tcp.connect(
					id, action.host, action.port,
					(connectResult) => {
						console.log(`Connection completed with result: ${connectResult}`);

						chrome.sockets.tcp.secure(id, {}, (secureResult) => {
							console.log(`TLS initialized with result: ${secureResult}`);

							chrome.sockets.tcp.setPaused(id, false, () => {
								console.log('Connection ready!')
							});
						});
					}
				);
			});
		}
	);
};

const handleError = (action: ErrorAction) => () => {
	console.error(action.message);
};

const aliasMap: AliasMap<SyncthingAction, ThunkAction<void, State, undefined>> = {
	[ActionType.FETCH_CERT]: handleFetchCert,
	[ActionType.CONNECT]: handleConnect,
	[ActionType.ERROR]: handleError
};

export default aliasMap;
