import { connect } from 'react-redux';
import { Dispatch } from 'redux';

import { fetchCert } from 'common/actions';
import { State } from 'common/state';

import App from '../components/App';

const mapStateToProps = (state: State) => {
	return {
		devices: state.devices
	};
};

const mapDispatchToProps = (dispatch: Dispatch<State>) => {
	return {
		onConnect: () => dispatch(fetchCert('192.168.1.200', 22000))
	};
};

export default connect(mapStateToProps, mapDispatchToProps)(App);
