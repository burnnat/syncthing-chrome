import { createStore, applyMiddleware } from 'redux';
import thunk from 'redux-thunk';
import { wrapStore, alias } from 'react-chrome-redux';

import { portName } from 'common/config';

import reducers from 'lib/reducers/all';
import aliases from 'lib/aliases';

wrapStore(
	createStore(
		reducers,
		applyMiddleware(
			alias(aliases),
			thunk
		)
	),
	{ portName }
);

chrome.app.runtime.onLaunched.addListener(() => {
	chrome.app.window.create('app.html', {
		outerBounds: {
			width: 600,
			height: 500
		}
	});
});
