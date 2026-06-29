// Babel config used by Jest (babel-jest). The webpack build continues to use
// .babelrc; this file only adds an env-specific preset for the test runner so
// ESM import/export is transpiled for Node without altering the build pipeline.
module.exports = (api) => {
  const isTest = api.env('test');
  return {
    presets: [
      '@babel/preset-react',
      ...(isTest ? [['@babel/preset-env', { targets: { node: 'current' } }]] : []),
    ],
  };
};
