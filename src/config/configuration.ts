import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import * as yaml from 'js-yaml';

const ENV = process.env.NODE_ENV || 'development';

export default () => {
  const configPath = join(process.cwd(), 'config', `${ENV}.yaml`);

  if (!existsSync(configPath)) {
    throw new Error(`Configuration file not found: ${configPath}`);
  }

  const fileContent = readFileSync(configPath, 'utf8');

  // Replace ${VAR} with environment variables for production
  const interpolated = fileContent.replace(
    /\$\{(\w+)\}/g,
    (_, varName) => process.env[varName] || '',
  );

  return yaml.load(interpolated) as Record<string, any>;
};
