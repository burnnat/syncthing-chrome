import * as React from 'react';

import MuiThemeProvider from 'material-ui/styles/MuiThemeProvider';
import createMuiTheme from 'material-ui/styles/theme';
import createPalette from 'material-ui/styles/palette';
import withStyles from 'material-ui/styles/withStyles';

import blue from 'material-ui/colors/blue';
import grey from 'material-ui/colors/grey';
import red from 'material-ui/colors/red';

import AppBar from 'material-ui/AppBar';
import Button from 'material-ui/Button';
import Toolbar from 'material-ui/Toolbar';
import Typography from 'material-ui/Typography';

import { Device } from 'common/state';

import DeviceInfo from './DeviceInfo';

const theme = createMuiTheme({
	palette: createPalette({
		primary: blue
	})
});

const styles = (theme) => ({
	button: {
		margin: theme.spacing.unit,
	}
});

interface AppProps {
	classes: {
		[name: string]: string
	},

	devices: Device[],

	onConnect: () => void
}

class App extends React.Component<AppProps> {
	render() {
		const css = this.props.classes;

		return (
			<MuiThemeProvider theme={theme}>
				<div>
					<AppBar position="static" color="primary">
						<Toolbar>
							<Typography type="title" color="inherit">
								SyncthingFS
							</Typography>
						</Toolbar>
					</AppBar>
					<Button
						className={css.button}
						raised={true}
						onClick={this.props.onConnect}>
						Connect to Server
					</Button>
					{ this.renderDevices() }
				</div>
			</MuiThemeProvider>
		);
	}

	renderDevices() {
		return this.props.devices.map(
			(device) => <DeviceInfo key={device.id} device={device} />
		);
	}
}

export default withStyles(styles)(App);