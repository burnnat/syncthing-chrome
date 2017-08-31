import * as React from 'react';
import * as ReactDOM from 'react-dom';
import jss from 'jss';

import App from './app/App';

const styles = {
	body: {
		margin: 0
	}
};

document.addEventListener(
	'DOMContentLoaded',
	() => {
		const {classes} = jss.createStyleSheet(styles).attach();
		document.body.className = classes.body;

		ReactDOM.render(
			React.createElement(App),
			document.getElementById('root')
		);
	}
);
