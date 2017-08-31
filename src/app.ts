import * as React from 'react';
import * as ReactDOM from 'react-dom';

import App from './app/App';

document.addEventListener(
	'DOMContentLoaded',
	() => {
		ReactDOM.render(
			React.createElement(App),
			document.getElementById('root')
		);
	}
);
