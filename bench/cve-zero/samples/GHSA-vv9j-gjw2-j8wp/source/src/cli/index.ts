import { readFileSync } from 'node:fs';
import process from 'node:process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import YeomanCommand, { addEnvironmentOptions } from '../util/command.ts';
import { createEnv as createEnvironment } from '../index.ts';
import { environmentAction, printGroupedGenerator } from './utils.ts';

const program = new YeomanCommand();

const packageJson = JSON.parse(readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../../package.json')).toString());

program.version(packageJson.version).allowExcessArguments(false).enablePositionalOptions();

addEnvironmentOptions(
  program
    .command('run <namespace>')
    .description('Run a generator')
    .argument('<namespace>', 'Generator to run')
    .passThroughOptions()
    .allowUnknownOption()
    .allowExcessArguments(true)
    .action(environmentAction)
    .usage('[environment options] <namespace> [generator-options]'),
);

program
  .command('find')
  .description('Find installed generators')
  .action(async () => {
    const environment = createEnvironment();
    printGroupedGenerator(await environment.lookup());
  });

program
  .command('list')
  .description('List generators available to be used')
  .action(async () => {
    const environment = createEnvironment();
    await environment.lookup();
    printGroupedGenerator(Object.values(environment.getGeneratorsMeta()));
  });

try {
  await program.parseAsync(process.argv);
} catch (error) {
  console.log(error);
  // eslint-disable-next-line unicorn/no-process-exit
  process.exit(1);
}
