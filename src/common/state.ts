export interface Device {
	id: string;
	cert: string;
}

export interface State {
	devices: Device[]
}
