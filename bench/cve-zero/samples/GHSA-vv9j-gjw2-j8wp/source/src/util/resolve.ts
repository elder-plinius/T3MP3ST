import { dirname, extname, join, normalize, resolve, sep } from 'node:path';
import { realpathSync, statSync } from 'node:fs';
import untildify from 'untildify';
import { locatePathSync } from 'locate-path';
import { defaultExtensions } from '../generator-lookup.ts';

/**
 * Resolve a module path
 * @param  specifier - Filepath or module name
 * @return           - The resolved path leading to the module
 */
export function resolveModulePath(specifier: string, resolvedOrigin?: string) {
  let maybeResolved = specifier;
  if (maybeResolved.startsWith('.')) {
    if (resolvedOrigin) {
      maybeResolved = resolve(dirname(resolvedOrigin), '..', maybeResolved);
    } else {
      throw new Error(`Specifier ${maybeResolved} could not be calculated`);
    }
  }

  maybeResolved = untildify(maybeResolved);
  maybeResolved = normalize(maybeResolved);

  if (extname(maybeResolved) === '') {
    maybeResolved += sep;
  }

  try {
    let specStat = statSync(maybeResolved);
    if (specStat.isSymbolicLink()) {
      specStat = statSync(realpathSync(maybeResolved));
    }

    if (specStat.isFile()) {
      return maybeResolved;
    }

    if (specStat.isDirectory()) {
      return locatePathSync(defaultExtensions.map(extension => `index${extension}`).map(file => join(maybeResolved, file)));
    }
  } catch {
    // ignore error
  }

  throw new Error(`Error resolving ${specifier}`);
}
