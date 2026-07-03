import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import type { BaseGeneratorConstructor, BaseGeneratorOptions, GeneratorEnvironmentOptions, InputOutputAdapter } from '@yeoman/types';
import { type YeomanNamespace, requireNamespace, toNamespace } from '@yeoman/namespace';
import { flyImport } from 'fly-import';
import { defaults, pick, uniq } from 'lodash-es';
import { valid } from 'semver';
import { type LookupOptions } from './generator-lookup.ts';
import YeomanCommand from './util/command.ts';
import EnvironmentBase, { type EnvironmentOptions } from './environment-base.ts';
import { splitArgsFromString as splitArgumentsFromString } from './util/util.ts';

class FullEnvironment extends EnvironmentBase {
  constructor(options?: EnvironmentOptions);
  constructor(options: EnvironmentOptions = {}, adapterCompat?: InputOutputAdapter) {
    if (adapterCompat) {
      options.adapter = adapterCompat;
    }

    super(options);

    this.loadSharedOptions(this.options);
    if (this.sharedOptions.skipLocalCache === undefined) {
      this.sharedOptions.skipLocalCache = true;
    }
  }

  /**
   * Load options passed to the Generator that should be used by the Environment.
   *
   * @param {Object} options
   */
  loadEnvironmentOptions(options: EnvironmentOptions) {
    const environmentOptions = pick(options, ['skipInstall', 'nodePackageManager']);
    defaults(this.options, environmentOptions);
    return environmentOptions;
  }

  /**
   * Load options passed to the Environment that should be forwarded to the Generator.
   *
   * @param {Object} options
   */
  loadSharedOptions(options: EnvironmentOptions) {
    const optionsToShare = pick(options, [
      'skipInstall',
      'forceInstall',
      'skipCache',
      'skipLocalCache',
      'skipParseOptions',
      'localConfigOnly',
      'askAnswered',
    ]);
    Object.assign(this.sharedOptions, optionsToShare);
    return optionsToShare;
  }

  /**
   * @protected
   * Outputs the general help and usage. Optionally, if generators have been
   * registered, the list of available generators is also displayed.
   *
   * @param {String} name
   */
  help(name = 'init') {
    const out = [
      'Usage: :binary: GENERATOR [args] [options]',
      '',
      'General options:',
      "  --help       # Print generator's options and usage",
      '  -f, --force  # Overwrite files that already exist',
      '',
      'Please choose a generator below.',
      '',
    ];

    const ns = this.namespaces();

    const groups: Record<string, string[]> = {};
    for (const namespace of ns) {
      const base = namespace.split(':')[0];

      if (!groups[base]) {
        groups[base] = [];
      }

      groups[base].push(namespace);
    }

    for (const key of Object.keys(groups).sort()) {
      const group = groups[key];

      if (group.length > 0) {
        out.push('', key.charAt(0).toUpperCase() + key.slice(1));
      }

      for (const ns of groups[key]) {
        out.push(`  ${ns}`);
      }
    }

    return out.join('\n').replaceAll(':binary:', name);
  }

  /**
   * @protected
   * Returns the list of registered namespace.
   * @return {Array}
   */
  namespaces() {
    return this.store.namespaces();
  }

  /**
   * @protected
   * Returns stored generators meta
   * @return {Object}
   */
  getGeneratorsMeta() {
    return this.store.getGeneratorsMeta();
  }

  /**
   * @protected
   * Get registered generators names
   *
   * @return {Array}
   */
  getGeneratorNames() {
    return uniq(Object.keys(this.getGeneratorsMeta()).map(namespace => toNamespace(namespace)?.packageNamespace));
  }

  /**
   * Get last added path for a namespace
   *
   * @param  {String} - namespace
   * @return {String} - path of the package
   */
  getPackagePath(namespace: string) {
    if (namespace.includes(':')) {
      const generator = this.getGeneratorMeta(namespace);
      return generator?.packagePath;
    }

    const packagePaths = this.getPackagePaths(namespace) || [];
    return packagePaths[0];
  }

  /**
   * Get paths for a namespace
   *
   * @param - namespace
   * @return array of paths.
   */
  getPackagePaths(namespace: string) {
    return (
      this.store.getPackagesPaths()[namespace] || this.store.getPackagesPaths()[requireNamespace(this.alias(namespace)).packageNamespace]
    );
  }

  /**
   * Generate a command for the generator and execute.
   *
   * @param {string} generatorNamespace
   * @param {string[]} args
   */
  async execute(generatorNamespace: string, arguments_ = []) {
    const namespace = requireNamespace(generatorNamespace);
    if (!(await this.get(namespace.namespace))) {
      await this.lookup({
        packagePatterns: [namespace.generatorHint],
        singleResult: true,
      });
    }

    if (!(await this.get(namespace.namespace))) {
      await this.installLocalGenerators({
        [namespace.generatorHint]: namespace.semver,
      });
    }

    const namespaceCommand = this.command ? this.command.command(namespace.namespace) : new YeomanCommand();
    namespaceCommand.usage('[generator-options]');

    // Instantiate the generator for options
    const generator = await this.create(namespace.namespace, { generatorArgs: [], generatorOptions: { help: true } });
    namespaceCommand.registerGenerator(generator);

    namespaceCommand.parse(arguments_, { from: 'user' });
    return this.run([namespace.namespace, ...namespaceCommand.args], {
      ...namespaceCommand.opts(),
    });
  }

  async requireGenerator(namespace: string): Promise<BaseGeneratorConstructor | undefined> {
    if (namespace === undefined) {
      try {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        // eslint-disable-next-line import-x/no-unresolved
        const { default: Generator } = await import('yeoman-generator');
        return Generator;
      } catch {
        // ignore error
      }

      const { default: Generator } = await flyImport('yeoman-generator');
      return Generator;
    }

    // Namespace is a version
    if (valid(namespace)) {
      // Create a hash to install any version range in the local repository
      const hash = createHash('shake256', { outputLength: 2 }).update(namespace, 'utf8').digest('hex');

      const { default: Generator } = await flyImport(`@yeoman/generator-impl-${hash}@npm:yeoman-generator@${namespace}`);
      return Generator;
    }

    return this.get(namespace);
  }

  /**
   * Install generators at the custom local repository and register.
   *
   * @param  {Object} packages - packages to install key(packageName): value(versionRange).
   * @return  {Boolean} - true if the install succeeded.
   */
  async installLocalGenerators(packages: Record<string, string | undefined>) {
    const entries = Object.entries(packages);
    const specs = entries.map(([packageName, version]) => `${packageName}${version ? `@${version}` : ''}`);
    const installResult = await this.repository.install(specs);
    const failToInstall = installResult.find(result => !result.path);
    if (failToInstall) {
      throw new Error(`Fail to install ${failToInstall.pkgid}`);
    }

    await this.lookup({ packagePaths: installResult.map(result => result.path) as string[] });
    return true;
  }

  /**
   * Lookup and register generators from the custom local repository.
   *
   * @param  {String[]} [packagesToLookup='generator-*'] - packages to lookup.
   */
  async lookupLocalPackages(packagesToLookup = ['generator-*']) {
    await this.lookup({
      packagePatterns: packagesToLookup,
      npmPaths: [join(this.repository.repositoryPath, 'node_modules')],
    });
  }

  /**
   * Lookup and register generators from the custom local repository.
   *
   * @private
   * @param  {YeomanNamespace[]} namespacesToLookup - namespaces to lookup.
   * @return {Promise<Object[]>} List of generators
   */
  async lookupLocalNamespaces(namespacesToLookup: string | string[]) {
    if (!namespacesToLookup) {
      return [];
    }

    namespacesToLookup = Array.isArray(namespacesToLookup) ? namespacesToLookup : [namespacesToLookup];
    const namespaces = namespacesToLookup.map(ns => requireNamespace(ns));
    // Keep only those packages that has a compatible version.
    return this.lookupLocalPackages(namespaces.map(ns => ns.generatorHint));
  }

  /**
   * Search for generators or sub generators by namespace.
   *
   * @private
   * @param {boolean|Object} [options] options passed to lookup. Options singleResult,
   *                                   filePatterns and packagePatterns can be overridden
   * @return {Array|Object} List of generators
   */
  async lookupNamespaces(namespaces: string | string[], options: LookupOptions = {}) {
    if (!namespaces) {
      return [];
    }

    namespaces = Array.isArray(namespaces) ? namespaces : [namespaces];
    const namespacesObjs = namespaces.map(ns => requireNamespace(ns));
    const options_ = namespacesObjs.map(ns => {
      const nsOptions: LookupOptions = { packagePatterns: [ns.generatorHint] };
      if (ns.generator) {
        // Build filePatterns to look specifically for the namespace.
        const genPath = ns.generator.split(':').join('/');
        let filePatterns = [`${genPath}/index.?s`, `${genPath}.?s`];
        const lookups = options.lookups ?? this.lookups;
        filePatterns = lookups.flatMap(prefix => filePatterns.map(pattern => join(prefix, pattern)));
        nsOptions.filePatterns = filePatterns;
        nsOptions.singleResult = true;
      }

      return nsOptions;
    });
    return Promise.all(options_.flatMap(async opt => this.lookup({ ...opt, ...options })));
  }

  /**
   * Load or install namespaces based on the namespace flag
   *
   * @private
   * @param  {String|Array} - namespaces
   * @return  {boolean} - true if every required namespace was found.
   */
  async prepareEnvironment(namespaces: string | string[]) {
    namespaces = Array.isArray(namespaces) ? namespaces : [namespaces];
    let missing = namespaces.map(ns => requireNamespace(ns));
    const updateMissing = async () => {
      const entries = await Promise.all(missing.map(async ns => [ns, await this.get(ns)]));
      missing = entries.filter(([_ns, gen]) => Boolean(gen)).map(([ns]) => ns) as YeomanNamespace[];
    };

    await updateMissing();

    // Install missing
    const toInstall: Record<string, string | undefined> = Object.fromEntries(missing.map(ns => [ns.generatorHint, ns.semver]));

    await this.installLocalGenerators(toInstall);

    await updateMissing();

    if (missing.length === 0) {
      return true;
    }

    throw new Error(`Error preparing environment for ${missing.map(ns => ns.complete).join(',')}`);
  }

  /**
   * Tries to locate and run a specific generator. The lookup is done depending
   * on the provided arguments, options and the list of registered generators.
   *
   * When the environment was unable to resolve a generator, an error is raised.
   */
  async run(
    arguments_?: string | string[],
    options: EnvironmentOptions & BaseGeneratorOptions & Partial<GeneratorEnvironmentOptions> = {},
  ) {
    arguments_ = Array.isArray(arguments_) ? arguments_ : splitArgumentsFromString(arguments_ as unknown as string);

    let name = arguments_.shift();
    if (!name) {
      throw new Error('Must provide at least one argument, the generator namespace to invoke.');
    }

    if (name.startsWith('.')) {
      name = resolve(name);
    }

    this.loadEnvironmentOptions(options);

    if (this.experimental && !this.getGeneratorMeta(name)) {
      try {
        await this.prepareEnvironment(name);
      } catch {
        // ignore error
      }
    }

    const generator = await this.create(name, {
      generatorArgs: arguments_,
      generatorOptions: options,
    });

    if (options.help) {
      console.log((generator as any).help());
      return;
    }

    return this.runGenerator(generator);
  }
}

export default FullEnvironment;
