import * as React from 'react';
import * as ReactDOM from 'react-dom';
import jss from 'jss';

import Root from 'app/components/Root';

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
			React.createElement(Root),
			document.getElementById('root')
		);
	}
);
