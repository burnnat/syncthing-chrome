const webpack = require("webpack");
const path = require('path');

const environment = process.env.NODE_ENV || 'development';
const isDevelopment = environment === 'development';

const resolve = (relative) => path.resolve(__dirname, relative);

const paths = {
	source: resolve('src'),
	output: resolve('dist/js')
}

const config = {
	context: paths.source,
	entry: {
		background: './app/background.ts'
	},
	output: {
		path: paths.output,
		filename: '[name].js'
	},
	module: {
		rules: [
			{
				exclude: /node_modules/,
				test: /\.tsx?$/,
				loader: 'ts-loader'
			},
			{
				test: require.resolve('node-forge/lib/tls'),
				loader: 'inject-loader',
				options: {
					append: (
						'forge.tls.internal = tls;\n' +
						'forge.tls.handlers = hsTable;\n'
					)
				}
			}
		]
	},
	resolve: {
		extensions: ['.ts', '.tsx', '.js']
	},
	resolveLoader: {
		alias: {
			'inject-loader': '../loaders/inject-loader.js'
		}
	},
	plugins: []
};

if (isDevelopment) {
	config.devtool = 'cheap-module-source-map';
}
else {
	config.plugins.push(new webpack.optimize.UglifyJsPlugin());
}

module.exports = config;
