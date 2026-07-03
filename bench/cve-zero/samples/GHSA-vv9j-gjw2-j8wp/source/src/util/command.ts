import { Command, Option } from 'commander';
import type BaseEnvironment from '../environment-base.ts';

export default class YeomanCommand extends Command {
  env?: BaseEnvironment;

  override createCommand(name?: string) {
    return new YeomanCommand(name);
  }

  /**
   * Override addOption to register a negative alternative for every option.
   * @param {Option} option
   * @return {YeomanCommand} this;
   */
  addOption(option: Option) {
    if (!option.long || option.required || option.optional) {
      return super.addOption(option);
    }

    if (option.negate) {
      // Add a affirmative option for negative boolean options.
      // Should be done before, because commander adds a non working affirmative by itself.
      super.addOption(new Option(option.long.replace(/^--no-/, '--')).hideHelp());
    }

    const result = super.addOption(option);
    if (!option.negate) {
      // Add a hidden negative option for affirmative boolean options.
      super.addOption(new Option(option.long.replace(/^--/, '--no-')).hideHelp());
    }

    return result;
  }

  /**
   * Load Generator options into a commander instance.
   *
   * @param {Generator} generator - Generator
   * @return {Command} return command
   */
  registerGenerator(generator: any) {
    return this.addGeneratorOptions(generator._options).addGeneratorArguments(generator._arguments);
  }

  /**
   * Register arguments using generator._arguments structure.
   * @param {object[]} generatorArgs
   * @return {YeomanCommand} this;
   */
  addGeneratorArguments(generatorArguments: any[] = []) {
    if (!generatorArguments || generatorArguments.length === 0) {
      return this;
    }

    const arguments_ = generatorArguments
      .map(argument => {
        const argumentName = argument.type === Array ? `${argument.name}...` : argument.name;
        return argument.required ? `<${argumentName}>` : `[${argumentName}]`;
      })
      .join(' ');
    this.arguments(arguments_);
    return this;
  }

  /**
   * Register options using generator._options structure.
   * @param {object} options
   * @param {string} blueprintOptionDescription - description of the blueprint that adds the option
   * @return {YeomanCommand} this;
   */
  addGeneratorOptions(options: Record<string, any>) {
    options = options || {};
    for (const [key, value] of Object.entries(options)) {
      this._addGeneratorOption(key, value);
    }

    return this;
  }

  #findOption(arg: string) {
    return this.options.find(option => option.short === arg || option.long === arg);
  }

  _addGeneratorOption(optionName: string, optionDefinition: any, additionalDescription = '') {
    if (optionName === 'help') {
      return;
    }

    const longOption = `--${optionName}`;
    const existingOption = this.#findOption(longOption);
    if (this.#findOption(longOption)) {
      return existingOption;
    }

    let cmdString = '';
    if (optionDefinition.alias) {
      cmdString = `-${optionDefinition.alias}, `;
    }

    cmdString = `${cmdString}${longOption}`;
    if (optionDefinition.type === String) {
      cmdString = optionDefinition.required === false ? `${cmdString} [value]` : `${cmdString} <value>`;
    } else if (optionDefinition.type === Array) {
      cmdString = optionDefinition.required === false ? `${cmdString} [value...]` : `${cmdString} <value...>`;
    }

    return this.addOption(
      new Option(cmdString, `${optionDefinition.description}${additionalDescription}`)
        .default(optionDefinition.default)
        .hideHelp(optionDefinition.hide),
    );
  }
}

/* Add Environment options */
export const addEnvironmentOptions = (command = new YeomanCommand()) =>
  command
    .option('--cwd', 'Path to use as current dir')
    /* Environment options */
    .option('--skip-install', 'Do not automatically install dependencies', false)
    /* Generator options */
    .option('--skip-cache', 'Do not remember prompt answers', false)
    .option('--local-config-only', 'Generate .yo-rc-global.json locally', false)
    .option('--ask-answered', 'Show prompts for already configured options', false)
    /* Conflicter options */
    .option('--force', 'Override every file', false)
    .option('--dry-run', 'Print conflicts', false)
    .option('--whitespace', 'Whitespace changes will not trigger conflicts', false)
    .option('--bail', 'Fail on first conflict', false)
    .option('--skip-yo-resolve', 'Ignore .yo-resolve files', false)
    /* Hidden options, used for api */
    .addOption(new Option('--skip-local-cache', 'Skip local answers cache').default(true).hideHelp())
    .addOption(new Option('--skip-parse-options', 'Skip legacy options parsing').default(false).hideHelp())
    .addOption(new Option('--experimental', 'Experimental features').default(false).hideHelp())
    .addOption(new Option('--log-cwd', 'Path for log purpose').hideHelp());
