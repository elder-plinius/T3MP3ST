import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { delimiter, dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';
import arrify from 'arrify';
import { compact, uniq } from 'lodash-es';
import { type Options as GlobbyOptions, globbySync } from 'globby';
import slash from 'slash';
import createdLogger from 'debug';
import { execaOutput } from './util/util.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PROJECT_ROOT = join(__dirname, '..');

const PACKAGE_NAME_PATTERN = [JSON.parse(readFileSync(join(PROJECT_ROOT, 'package.json')).toString()).name];

const win32 = process.platform === 'win32';
const nvm = process.env.NVM_HOME;

const debug = createdLogger('yeoman:environment');

export type ModuleLookupOptions = {
  /** Set true to skip lookups of globally-installed generators */
  localOnly?: boolean;
  /** Paths to look for generators */
  packagePaths?: string[];
  /** Repository paths to look for generators packages */
  npmPaths?: string[];
  /** File pattern to look for */
  filePatterns?: string[];
  /** The package patterns to look for */
  packagePatterns?: string[];
  /** A value indicating whether the lookup should be stopped after finding the first result */
  singleResult?: boolean;
  filterPaths?: boolean;
  /** Set true reverse npmPaths/packagePaths order */
  reverse?: boolean;
  /** The `deep` option to pass to `globby` */
  globbyDeep?: number;
  globbyOptions?: any;
};

/**
 * Search for npm packages.
 */
export function moduleLookupSync(
  options: ModuleLookupOptions,
  find: (argument: { files: string[]; packagePath: string }) => string | undefined,
) {
  debug('Running lookup with options: %o', options);
  options = { ...options };
  options.filePatterns = arrify(options.filePatterns ?? 'package.json').map(filePattern => slash(filePattern));

  if (options.packagePaths) {
    options.packagePaths = arrify(options.packagePaths);
    if (options.reverse) {
      options.packagePaths = options.packagePaths.toReversed();
    }
  } else {
    options.npmPaths = options.npmPaths ?? getNpmPaths(options);
    if (options.reverse && Array.isArray(options.npmPaths)) {
      options.npmPaths = options.npmPaths.toReversed();
    }

    options.packagePatterns = arrify(options.packagePatterns ?? PACKAGE_NAME_PATTERN).map(packagePattern => slash(packagePattern));
    options.packagePaths = findPackagesIn(options.npmPaths, options.packagePatterns);
  }

  debug('Lookup calculated options: %o', options);

  const modules = [];
  for (const packagePath of options.packagePaths) {
    if (!existsSync(packagePath) || (!lstatSync(packagePath).isDirectory() && !lstatSync(packagePath).isSymbolicLink())) {
      continue;
    }

    const files = globbySync(options.filePatterns, {
      cwd: packagePath,
      absolute: true,
      ...options.globbyOptions,
    } as GlobbyOptions);

    const filePath = find({ files, packagePath });
    if (filePath) {
      return [{ filePath, packagePath }];
    }

    for (const filePath of files) {
      modules.push({ filePath, packagePath });
    }
  }

  return modules;
}

/**
 * Search npm for every available generators.
 * Generators are npm packages who's name start with `generator-` and who're placed in the
 * top level `node_module` path. They can be installed globally or locally.
 *
 * @method
 *
 * @param searchPaths List of search paths
 * @param packagePatterns Pattern of the packages
 * @param globbyOptions
 * @return List of the generator modules path
 */
export function findPackagesIn(searchPaths: string[], packagePatterns: string[], globbyOptions?: any): any[] {
  searchPaths = arrify(searchPaths)
    .filter(Boolean)
    .map(npmPath => resolve(npmPath));
  let modules: any[] = [];
  for (const root of searchPaths) {
    if (!existsSync(root) || (!lstatSync(root).isDirectory() && !lstatSync(root).isSymbolicLink())) {
      continue;
    }

    // Some folders might not be readable to the current user. For those, we add a try
    // catch to handle the error gracefully as globby doesn't have an option to skip
    // restricted folders.
    try {
      modules = modules.concat(
        globbySync(packagePatterns, {
          cwd: root,
          onlyDirectories: true,
          expandDirectories: false,
          absolute: true,
          deep: 0,
          ...globbyOptions,
        } as GlobbyOptions),
      );

      // To limit recursive lookups into non-namespace folders within globby,
      // fetch all namespaces in root, then search each namespace separately
      // for generator modules
      const scopes = globbySync(['@*'], {
        cwd: root,
        onlyDirectories: true,
        expandDirectories: false,
        absolute: true,
        deep: 0,
        ...globbyOptions,
      } as GlobbyOptions);

      for (const scope of scopes) {
        modules = modules.concat(
          globbySync(packagePatterns, {
            cwd: scope,
            onlyDirectories: true,
            expandDirectories: false,
            absolute: true,
            deep: 0,
            ...globbyOptions,
          } as GlobbyOptions),
        );
      }
    } catch (error) {
      debug('Could not access %s (%s)', root, error);
    }
  }

  return modules;
}

/**
 * Get the npm lookup directories (`node_modules/`)
 *
 * @method
 *
 * @param {boolean|Object} [options]
 * @param {boolean} [options.localOnly = false] - Set true to skip lookups of
 *                                               globally-installed generators.
 * @param {boolean} [options.filterPaths = false] - Remove paths that don't ends
 *                       with a supported path (don't touch at NODE_PATH paths).
 * @return {Array} lookup paths
 */
export function getNpmPaths(options: { localOnly?: boolean; filterPaths?: boolean } = {}): string[] {
  // Resolve signature where options is boolean (localOnly).
  if (typeof options === 'boolean') {
    options = { localOnly: options };
  }

  // Start with the local paths.
  let paths = getLocalNpmPaths();

  // Append global paths, unless they should be excluded.
  if (!options.localOnly) {
    paths = paths.concat(getGlobalNpmPaths(options.filterPaths));
  }

  return uniq(paths);
}

/**
 * Get the local npm lookup directories
 * @private
 * @return {Array} lookup paths
 */
function getLocalNpmPaths(): string[] {
  const paths: string[] = [];

  // Walk up the CWD and add `node_modules/` folder lookup on each level
  process
    .cwd()
    .split(sep)
    .forEach((part, index, parts) => {
      let lookup = join(...parts.slice(0, index + 1), 'node_modules');

      if (!win32) {
        lookup = `/${lookup}`;
      }

      paths.push(lookup);
    });

  return uniq(paths.toReversed());
}

/**
 * Get the global npm lookup directories
 * Reference: https://nodejs.org/api/modules.html
 * @private
 * @return {Array} lookup paths
 */
function getGlobalNpmPaths(filterPaths = true): string[] {
  let paths: string[] = [];

  // Node.js will search in the following list of GLOBAL_FOLDERS:
  // 1: $HOME/.node_modules
  // 2: $HOME/.node_libraries
  // 3: $PREFIX/lib/node
  const filterValidNpmPath = function (path: string, ignore = false): string[] {
    return ignore ? [path] : ['/node_modules', '/.node_modules', '/.node_libraries', '/node'].some(dir => path.endsWith(dir)) ? [path] : [];
  };

  // Default paths for each system
  if (nvm && process.env.NVM_HOME) {
    paths.push(join(process.env.NVM_HOME, process.version, 'node_modules'));
  } else if (win32 && process.env.APPDATA) {
    paths.push(join(process.env.APPDATA, 'npm/node_modules'));
  } else {
    paths.push('/usr/lib/node_modules', '/usr/local/lib/node_modules');
  }

  // Add NVM prefix directory
  if (process.env.NVM_PATH) {
    paths.push(join(dirname(process.env.NVM_PATH), 'node_modules'));
  }

  // Adding global npm directories
  // We tried using npm to get the global modules path, but it haven't work out
  // because of bugs in the parseable implementation of `ls` command and mostly
  // performance issues. So, we go with our best bet for now.
  if (process.env.NODE_PATH) {
    paths = compact(process.env.NODE_PATH.split(delimiter)).concat(paths);
  }

  // Global node_modules should be 4 or 2 directory up this one (most of the time)
  // Ex: /usr/another_global/node_modules/yeoman-denerator/node_modules/yeoman-environment/lib (1 level dependency)
  paths.push(...filterValidNpmPath(join(PROJECT_ROOT, '../../..'), !filterPaths));
  // Ex: /usr/another_global/node_modules/yeoman-environment/lib (installed directly)
  // eslint-disable-next-line unicorn/prefer-single-call
  paths.push(join(PROJECT_ROOT, '..'));

  // Get yarn global directory and infer the module paths from there
  const yarnBase = execaOutput('yarn', ['global', 'dir']);
  if (yarnBase) {
    paths.push(resolve(yarnBase, 'node_modules'), resolve(yarnBase, '../link/'));
  }

  if (process.env.PNPM_HOME) {
    const pnpmHome = process.env.PNPM_HOME;
    paths.push(
      ...globbySync('global/*/node_modules', {
        cwd: pnpmHome,
        onlyDirectories: true,
        suppressErrors: true,
        absolute: true,
      }).map(modulesPath => resolve(modulesPath)),
    );
  }

  // Get npm global prefix and infer the module paths from there
  const globalInstall = execaOutput('npm', ['root', '-g']);
  if (globalInstall) {
    paths.push(resolve(globalInstall));
  }

  // Adds support for generator resolving when yeoman-generator has been linked
  if (process.argv[1]) {
    paths.push(...filterValidNpmPath(join(dirname(process.argv[1]), '../..'), !filterPaths));
  }

  return uniq(paths.filter(Boolean).toReversed());
}
