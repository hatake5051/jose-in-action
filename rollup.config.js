import includePaths from 'rollup-plugin-includepaths';
import resolve from 'rollup-plugin-node-resolve';
export default {
  input: 'build/index.js',
  output: {
    file: 'bundle.js',
    format: 'cjs',
  },
  plugins: [resolve(), includePaths({ paths: ['./build'] })],
};
