import * as React from 'react';
import { Provider } from 'react-redux';
import { Store } from 'react-chrome-redux';

import { portName } from 'common/config';
import { State } from 'common/state';

import App from '../containers/App';

interface RootState {
	loaded: boolean;
}

export default class Root extends React.Component<{}, RootState> {

	private store: Store<State>;

	constructor(props) {
		super(props);

		this.state = { loaded: false };
		this.store = new Store({ portName });

		const unsubscribe = this.store.subscribe(
			() => {
				unsubscribe();
				this.setState({ loaded: true });
			}
		);
	}

	render() {
		if (this.state.loaded) {
			return (
				<Provider store={this.store}>
					<App />
				</Provider>
			);
		}
		else {
			return <div/>;
		}
	}
}
