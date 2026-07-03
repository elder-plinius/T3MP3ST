import { extname, isAbsolute, join, posix } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { LookupOptions as LookupOptionsApi } from '@yeoman/types';
import { requireNamespace, toNamespace } from '@yeoman/namespace';
import { type ModuleLookupOptions, findPackagesIn, getNpmPaths, moduleLookupSync } from './module-lookup.ts';
import { asNamespace, defaultLookups } from './util/namespace.ts';

export type LookupOptions = LookupOptionsApi &
  ModuleLookupOptions & {
    lookups?: string[];
  };

type LookupMeta = { filePath: string; packagePath: string; lookups: string[] };

export const defaultExtensions = ['.ts', '.cts', '.mts', '.js', '.cjs', '.mjs'];

/**
 * Search for generators and their sub generators.
 *
 * A generator is a `:lookup/:name/index.js` file placed inside an npm package.
 *
 * Defaults lookups are:
 *   - ./
 *   - generators/
 *   - lib/generators/
 *
 * So this index file `node_modules/generator-dummy/lib/generators/yo/index.js` would be
 * registered as `dummy:yo` generator.
 *
 * @param {boolean|Object} [options]
 * @param {boolean} [options.localOnly = false] - Set true to skip lookups of
 *                                               globally-installed generators.
 * @param {string|Array} [options.packagePaths] - Paths to look for generators.
 * @param {string|Array} [options.npmPaths] - Repository paths to look for generators packages.
 * @param {string|Array} [options.filePatterns='*\/index.js'] - File pattern to look for.
 * @param {string|Array} [options.packagePatterns='generator-*'] - Package pattern to look for.
 * @param {boolean}      [options.singleResult=false] - Set true to stop lookup on the first match.
 * @param {Number}       [options.globbyDeep] - Deep option to be passed to globby.
 * @return {Promise<Object[]>} List of generators
 */
export async function lookupGenerators(options: LookupOptions = {}, register?: (meta: LookupMeta) => boolean) {
  const { lookups = defaultLookups } = options;
  options = {
    // Js generators should be after, last will override registered one.
    filePatterns: lookups.flatMap(prefix => defaultExtensions.map(extension => `${prefix}/*/index${extension}`)),
    filterPaths: false,
    packagePatterns: ['generator-*'],
    reverse: !options.singleResult,
    ...options,
  };

  return moduleLookupSync(options, ({ packagePath, files }) => {
    files = [...files].sort((a, b) => {
      return defaultExtensions.indexOf(extname(a)) - defaultExtensions.indexOf(extname(b));
    });
    for (const filePath of files) {
      const registered = register?.({ filePath, packagePath, lookups });
      if (options.singleResult && registered) {
        return filePath;
      }
    }

    return;
  });
}

/**
 * Lookup for a specific generator.
 *
 * @param  {String} namespace
 * @param  {Object} [options]
 * @param {Boolean} [options.localOnly=false] - Set true to skip lookups of
 *                                                     globally-installed generators.
 * @param {Boolean} [options.packagePath=false] - Set true to return the package
 *                                                       path instead of generators file.
 * @param {Boolean} [options.singleResult=true] - Set false to return multiple values.
 * @return {String} generator
 */
export function lookupGenerator(namespace: string, options?: ModuleLookupOptions & { packagePath?: boolean; generatorPath?: boolean }) {
  options = typeof options === 'boolean' ? { localOnly: options } : (options ?? {});
  options.singleResult = options.singleResult ?? true;

  options.filePatterns = options.filePatterns ?? defaultLookups.map(prefix => join(prefix, '*/index.{js,ts}'));
  const ns = requireNamespace(namespace);
  options.packagePatterns = options.packagePatterns ?? [ns.generatorHint];

  options.npmPaths = options.npmPaths ?? getNpmPaths({ localOnly: options.localOnly }).toReversed();
  options.packagePatterns = options.packagePatterns ?? ['generator-*'];
  options.packagePaths = options.packagePaths ?? findPackagesIn(options.npmPaths, options.packagePatterns);

  let paths: string[] | string | undefined = options.singleResult ? undefined : [];
  moduleLookupSync(options, ({ files, packagePath }) => {
    for (const filename of files) {
      const fileNs = asNamespace(filename, { lookups: defaultLookups });
      const ns = toNamespace(fileNs);
      if (namespace === fileNs || (options!.packagePath && namespace === ns?.packageNamespace)) {
        // Version 2.6.0 returned pattern instead of modulePath for options.packagePath
        const returnPath = options!.packagePath ? packagePath : options!.generatorPath ? posix.join(filename, '../../') : filename;
        if (options!.singleResult) {
          paths = returnPath;
          return filename;
        }

        (paths as string[]).push(returnPath);
      }
    }

    return;
  });

  if (options.singleResult) {
    const generatorPath = paths as unknown as string;
    return generatorPath && isAbsolute(generatorPath) ? pathToFileURL(generatorPath).toString() : generatorPath;
  }

  return paths!.map(gen => (isAbsolute(gen) ? pathToFileURL(gen).toString() : gen));
}
