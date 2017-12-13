var path = require('path');
var fs = require('fs');

function resolve (dir) {
  return path.join(__dirname, dir)
}

var nodeExternals = fs.readdirSync("node_modules").reduce(function(acc, mod) {
  if (mod === ".bin") {
    return acc
  }

  acc[mod] = "commonjs " + mod
  return acc
}, {})

module.exports = {
  entry: './src/index.js',
  node: {
    __filename: true,
    __dirname: true
  },
  target: 'node',
  output: {
    path: path.join(__dirname, 'lib'),
    filename: 'index.js',
    library: 'SuperLogin',
    libraryTarget: 'umd'
  },
  externals: nodeExternals,
  resolve: {
    extensions: ['.js', '.json'],
    alias: {
      '@': resolve('src')
    }
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader'
        }
      }
    ]
  }
}