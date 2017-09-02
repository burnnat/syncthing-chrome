import * as React from 'react';

import Typography from 'material-ui/Typography';

import { Device } from 'common/state';

interface DeviceInfoProps {
	device: Device
}

export default class DeviceInfo extends React.Component<DeviceInfoProps> {
	render() {
		return (
			<div>
				<Typography type="body2">Device ID:</Typography>
				<Typography type="body1">{ this.props.device.id }</Typography>
				<Typography type="body2">Certificate:</Typography>
				<Typography type="body1">{ this.props.device.cert }</Typography>
			</div>
		);
	}
}
