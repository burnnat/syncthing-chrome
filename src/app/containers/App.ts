import { connect } from 'react-redux';
import { Dispatch } from 'redux';

import { fetchCert, connect as connectDevice, error } from 'common/actions';
import { State } from 'common/state';

import App from '../components/App';

const mapStateToProps = (state: State) => {
	return {
		devices: state.devices
	};
};

const mapDispatchToProps = (dispatch: Dispatch<State>) => {
	return {
		onLookupDevice: () => dispatch(fetchCert('192.168.1.200', 22000)),
		onConnect: () => dispatch(connectDevice('192.168.1.200', 22000)),
		onError: (message) => dispatch(error(message))
	};
};

export default connect(mapStateToProps, mapDispatchToProps)(App);
