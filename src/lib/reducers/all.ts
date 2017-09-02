import { concat } from 'lodash';
import { Reducer, combineReducers } from 'redux';

import { ActionType, SyncthingAction } from 'common/action-type';
import { Device, State } from 'common/state';

const devices: Reducer<Device[]> = (state = [], action: SyncthingAction) => {
	if (action.type === ActionType.REGISTER_DEVICE) {
		return concat(
			state,
			{
				id: action.id,
				cert: action.cert
			}
		);
	}
	else {
		return state;
	}
};

const all: Reducer<State> = combineReducers({
	devices
});

export default all;
