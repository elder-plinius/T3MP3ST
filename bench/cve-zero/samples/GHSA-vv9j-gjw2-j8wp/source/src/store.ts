import { pathToFileURL } from 'node:url';
import { extname, join } from 'node:path';
import { createRequire } from 'node:module';
import { toNamespace } from '@yeoman/namespace';
import type {
  BaseEnvironment,
  BaseGenerator,
  BaseGeneratorConstructorMeta,
  BaseGeneratorMeta,
  GeneratorMeta,
  GetGeneratorConstructor,
} from '@yeoman/types';
import createDebug from 'debug';

const debug = createDebug('yeoman:environment:store');
const require = createRequire(import.meta.url);

/**
 * The Generator store
 * This is used to store generator (npm packages) reference and instantiate them when
 * requested.
 * @constructor
 * @private
 */
export default class Store {
  private readonly _meta: Record<string, GeneratorMeta> = {};
  // Store packages paths by ns
  private readonly _packagesPaths: Record<string, string[]> = {};
  // Store packages ns
  private readonly _packagesNS: string[] = [];

  private readonly environment: BaseEnvironment;

  constructor(environment: BaseEnvironment) {
    this.environment = environment;
  }

  /**
   * Store a module under the namespace key
   * @param meta
   * @param generator - A generator module or a module path
   */
  add<M extends BaseGeneratorMeta>(meta: M, Generator?: unknown): GeneratorMeta & M {
    if (typeof meta.resolved === 'string') {
      if (extname(meta.resolved)) {
        meta.resolved = join(meta.resolved);
      } else {
        try {
          // Resolve if meta.resolved is a package path.
          meta.resolved = require.resolve(meta.resolved);
        } catch {
          // Import must be a file, append index.js to directories
          meta.resolved = join(meta.resolved, 'index.js');
        }
      }
    }

    if (meta.packagePath) {
      meta.packagePath = join(meta.packagePath);
    }

    let importModule: (() => Promise<unknown>) | undefined;
    if (!Generator) {
      if (!meta.resolved) {
        throw new Error(`Generator Stub or resolved path is required for ${meta.namespace}`);
      }

      importModule = () => {
        try {
          return require(meta.resolved!);
        } catch (error: any) {
          if (error.code === 'ERR_REQUIRE_ESM' || error.code === 'ERR_REQUIRE_ASYNC_MODULE') {
            return import(pathToFileURL(meta.resolved!).href);
          }
          throw error;
        }
      };
    }

    let importPromise: Promise<unknown> | undefined;
    // eslint-disable-next-line prefer-const
    let generatorMeta: (GeneratorMeta & M) | undefined;

    const importGenerator: GeneratorMeta['importGenerator'] = <G extends BaseGenerator>():
      | Promise<GetGeneratorConstructor<G> & BaseGeneratorConstructorMeta>
      | (GetGeneratorConstructor<G> & BaseGeneratorConstructorMeta) => {
      const handleImport = () => {
        if (importModule && !Generator) {
          const maybeModule = importModule();
          if ((maybeModule as any).then) {
            importPromise = maybeModule;
            return maybeModule
              .then((mod: any) => {
                Generator = mod;
              })
              .finally(() => {
                importPromise = undefined;
              });
          } else {
            Generator = maybeModule;
          }
        }
      };

      const handleModule = <G extends BaseGenerator>():
        | Promise<GetGeneratorConstructor<G> & BaseGeneratorConstructorMeta>
        | (GetGeneratorConstructor<G> & BaseGeneratorConstructorMeta) => {
        const factory = this.getFactory(Generator);
        if (typeof factory === 'function') {
          importPromise = factory(this.environment);
          return Promise.resolve(importPromise).then((mod: any) => {
            const generator = this._getGenerator<G>(mod, meta, generatorMeta);
            Generator = generator;
            importPromise = undefined;
            return generator;
          });
        }

        return this._getGenerator<G>(Generator, meta, generatorMeta);
      };

      if (importPromise) {
        return importPromise.then(() => Promise.resolve(handleImport()).then(() => handleModule()));
      }

      const maybeImportPromise = handleImport();
      if (maybeImportPromise?.then) {
        return maybeImportPromise.then(() => handleModule());
      }
      return handleModule();
    };

    const instantiate: GeneratorMeta['instantiate'] = async <G extends BaseGenerator>(arguments_: string[] = [], options: any = {}) =>
      this.environment.instantiate<G>(await importGenerator<G>(), { generatorArgs: arguments_, generatorOptions: options });
    const instantiateHelp: GeneratorMeta['instantiateHelp'] = async () => instantiate([], { help: true });
    const { packageNamespace } = toNamespace(meta.namespace) ?? {};

    generatorMeta = {
      ...meta,
      importGenerator,
      importModule,
      instantiate,
      instantiateHelp,
      packageNamespace,
    };
    this._meta[meta.namespace] = generatorMeta;

    if (packageNamespace) {
      this.addPackageNamespace(packageNamespace);
      if (meta.packagePath) {
        this.addPackage(packageNamespace, meta.packagePath);
      }
    }

    return generatorMeta;
  }

  /**
   * Get the module registered under the given namespace
   * @param  {String} namespace
   * @return {Module}
   */
  async get(namespace: string): Promise<GetGeneratorConstructor | undefined> {
    return this.getMeta(namespace)?.importGenerator();
  }

  /**
   * Get the module registered under the given namespace
   * @param  {String} namespace
   * @return {Module}
   */
  getMeta(namespace: string): GeneratorMeta | undefined {
    return this._meta[namespace];
  }

  /**
   * Returns the list of registered namespace.
   * @return {Array} Namespaces array
   */
  namespaces() {
    return Object.keys(this._meta);
  }

  /**
   * Get the stored generators meta data
   * @return {Object} Generators metadata
   */
  getGeneratorsMeta() {
    return this._meta;
  }

  /**
   * Store a package under the namespace key
   * @param {String}     packageNS - The key under which the generator can be retrieved
   * @param {String}   packagePath - The package path
   */
  addPackage(packageNS: string, packagePath: string) {
    if (this._packagesPaths[packageNS]) {
      // Yo environment allows overriding, so the last added has preference.
      if (this._packagesPaths[packageNS][0] !== packagePath) {
        const packagePaths = this._packagesPaths[packageNS];
        debug(
          'Overriding a package with namespace %s and path %s, with path %s',
          packageNS,
          this._packagesPaths[packageNS][0],
          packagePath,
        );
        // Remove old packagePath
        const index = packagePaths.indexOf(packagePath);
        if (index !== -1) {
          packagePaths.splice(index, 1);
        }

        packagePaths.splice(0, 0, packagePath);
      }
    } else {
      this._packagesPaths[packageNS] = [packagePath];
    }
  }

  /**
   * Get the stored packages namespaces with paths.
   * @return {Object} Stored packages namespaces with paths.
   */
  getPackagesPaths() {
    return this._packagesPaths;
  }

  /**
   * Store a package ns
   * @param {String} packageNS - The key under which the generator can be retrieved
   */
  addPackageNamespace(packageNS: string) {
    if (!this._packagesNS.includes(packageNS)) {
      this._packagesNS.push(packageNS);
    }
  }

  /**
   * Get the stored packages namespaces.
   * @return {Array} Stored packages namespaces.
   */

  getPackagesNS(): string[] {
    return this._packagesNS;
  }

  private getFactory(module: any) {
    // CJS is imported in default, for backward compatibility we support a Generator exported as `module.exports = { default }`
    return module.createGenerator ?? module.default?.createGenerator ?? module.default?.default?.createGenerator;
  }

  private _getGenerator<G extends BaseGenerator>(
    module: any,
    meta: BaseGeneratorMeta,
    generatorMeta: BaseGeneratorMeta | undefined,
  ): GetGeneratorConstructor<G> & BaseGeneratorConstructorMeta {
    const Generator = module.default?.default ?? module.default ?? module;
    if (typeof Generator !== 'function') {
      throw new TypeError("The generator doesn't provide a constructor.");
    }

    Object.assign(Generator, meta);
    Generator._meta = generatorMeta;
    return Generator;
  }
}
