import esm from '@presetter/preset-esm';
import strict from '@presetter/preset-strict';
import { preset } from 'presetter';

import { name } from './package.json';

export default preset(name, {
  extends: [esm, strict],
  scripts: {
    // the e2e suite boots real Verdaccio installs against the built plugin, so build first
    'pretest:e2e:build': 'run build',
  },
});
