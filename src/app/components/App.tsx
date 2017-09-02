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
	};

	devices: Device[];

	onLookupDevice: () => void;
	onDownloadCert: () => void;
	onConnect: () => void;
	onError: (error: any) => void;
}

class App extends React.Component<AppProps> {

	constructor(props) {
		super(props);

		this.handleDownloadCert = this.handleDownloadCert.bind(this);
	}

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
						onClick={this.props.onLookupDevice}>
						Lookup Device
					</Button>
					<Button
						className={css.button}
						raised={true}
						onClick={this.handleDownloadCert}>
						Download Certificate
					</Button>
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

	handleDownloadCert() {
		const device = this.props.devices[0];

		chrome.fileSystem.chooseEntry(
			{
				type: 'saveFile',
				suggestedName: device.id.substring(0, 7) + '.pem',
				accepts: [
					{
						description: 'PEM Certificate (*.pem; *.crt)',
						mimeTypes: ['application/x-pem-file'],
						extensions: ['pem', 'crt']
					}
				]
			},
			(entry: FileEntry) => {
				entry.createWriter(
					(writer) => writer.write(
						new Blob(
							[this.props.devices[0].cert],
							{ type: 'application/x-pem-file' }
						)
					),
					this.props.onError
				);
			}
		);
	}
}

export default withStyles(styles)(App);
