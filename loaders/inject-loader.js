const loaderUtils = require('loader-utils');

module.exports = function(source, map) {
	const options = loaderUtils.getOptions(this);
	const result = (options.prepend || '') + source + (options.append || '');

	this.callback(null, result, map)
};
