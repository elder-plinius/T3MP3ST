import type { BaseGeneratorConstructor, GeneratorMeta } from '@yeoman/types';
import YeomanCommand, { addEnvironmentOptions } from './util/command.ts';
import { createEnv as createEnvironment } from './index.ts';

export type CommandPreparation = {
  resolved?: string;
  command?: YeomanCommand;
  generator?: BaseGeneratorConstructor;
  namespace?: string;
};

/**
 * Prepare a commander instance for cli support.
 *
 * @param {Command} command - Command to be prepared
 * @param  generatorPath - Generator to create Command
 * @return {Command} return command
 */
export const prepareGeneratorCommand = async ({
  command = addEnvironmentOptions(new YeomanCommand()),
  resolved,
  generator,
  namespace,
}: CommandPreparation) => {
  const environment = createEnvironment();
  let meta: GeneratorMeta;
  if (generator && namespace) {
    meta = environment.register(generator, { namespace, resolved });
  } else if (resolved) {
    meta = environment.register(resolved, { namespace });
  } else {
    throw new Error(`A generator with namespace or a generator path is required`);
  }

  command.env = environment;
  command.registerGenerator(await meta.instantiateHelp());
  command.action(async function (this: YeomanCommand) {
    let rootCommand: YeomanCommand = this;
    while (rootCommand.parent) {
      rootCommand = rootCommand.parent as YeomanCommand;
    }

    const generator = await meta.instantiate(this.args, this.opts());
    await environment.runGenerator(generator);
  });
  return command;
};

/**
 * Prepare a commander instance for cli support.
 *
 * @param generatorPaht - Generator to create Command
 * @return Return a Command instance
 */
export const prepareCommand = async (options: CommandPreparation) => {
  options.command = options.command ?? new YeomanCommand();
  addEnvironmentOptions(options.command);
  return prepareGeneratorCommand(options);
};
