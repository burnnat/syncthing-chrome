process.env.NODE_ENV = 'development';

const http = require('http');
const url = require('url');
const path = require('path');
const fs = require('fs');

const webpack = require('webpack');
const config = require('./webpack.config.js');

const isRemoteWorkspace = !!process.env.C9_PROJECT;
let packagedApp = null;

webpack(config).watch({}, (err, stats) => {
	if (err) {
		console.error(err.stack || err);

		if (err.details) {
			console.error(err.details);
		}

		return;
	}

	const info = stats.toJson();

	if (stats.hasErrors()) {
		console.error(info.errors);
	}

	if (stats.hasWarnings()) {
		console.warn(info.warnings);
	}

	console.log(
		stats.toString({
			chunks: false,
			colors: true
		})
	);

	if (isRemoteWorkspace) {
		console.log('Compiling application CRX...');

		const keyPath = 'key.pem';
		let keyVal;

		if (!fs.existsSync(keyPath)) {
			console.log('    ...generating private key...');
			const rsa = require('node-rsa');
			const key = new rsa({b: 2048});
			keyVal = key.exportKey('pkcs1-private-pem');
			fs.writeFileSync(keyPath, keyVal, 'UTF8');
		}
		else {
			keyVal = fs.readFileSync(keyPath, 'UTF8');
		}

		const ChromeExtension = require('crx');
		const crx = new ChromeExtension({
			privateKey: keyVal
		});

		crx.load(path.resolve(__dirname, './dist'))
			.then(crx => crx.pack())
			.then(crxBuffer => packagedApp = crxBuffer)
			.then(
				() => console.log('    ...completed!'),
				(err) => console.error('Error compiling CRX: ' + err)
			);
	}
});

if (isRemoteWorkspace) {
	const server = http.createServer(function(request, response) {
		response.writeHead(200, {
			'Content-Description': 'File Transfer',
			'Content-Type': 'application/x-chrome-extension',
			'Content-Disposition': 'attachment; filename=syncthing-chrome.crx',
			'Content-Transfer-Encoding': 'binary'
		});

		response.write(packagedApp, 'binary');

		response.end();
	});

	server.listen(process.env.PORT, process.env.IP);

	console.log('Serving chrome app at: http://' + process.env.C9_HOSTNAME + '/');
}
