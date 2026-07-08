import { parse } from 'node:path';
import slash from 'slash';
import { escapeRegExp, findLast } from 'lodash-es';

type AsNamespaceOptions = {
  lookups?: string[];
};

export const defaultLookups = ['.', 'generators', 'lib/generators', 'dist/generators'];

/**
 * Given a String `filepath`, tries to figure out the relative namespace.
 *
 * ### Examples:
 *
 *     this.namespace('backbone/all/index.js');
 *     // => backbone:all
 *
 *     this.namespace('generator-backbone/model');
 *     // => backbone:model
 *
 *     this.namespace('backbone.js');
 *     // => backbone
 *
 *     this.namespace('generator-mocha/backbone/model/index.js');
 *     // => mocha:backbone:model
 *
 * @param filepath
 * @param lookups paths
 */
export const asNamespace = (filepath: string, { lookups = defaultLookups }: AsNamespaceOptions): string => {
  if (!filepath) {
    throw new Error('Missing file path');
  }

  // Normalize path
  let ns = slash(filepath);

  // Ignore path before latest node_modules
  const nodeModulesPath = '/node_modules/';
  if (ns.includes(nodeModulesPath)) {
    ns = ns.slice(ns.lastIndexOf(nodeModulesPath) + nodeModulesPath.length);
  }

  // Cleanup extension and normalize path for differents OS
  const parsed = parse(ns);
  ns = parsed.dir ? `${parsed.dir}/${parsed.name}` : parsed.name;

  // Sort lookups by length so biggest are removed first
  const nsLookups = [...lookups, '..']
    .map(found => slash(found))
    .sort((a, b) => a.split('/').length - b.split('/').length)
    .toReversed();

  // If `ns` contains a lookup dir in its path, remove it.
  for (const lookup of nsLookups) {
    // Only match full directory (begin with leading slash or start of input, end with trailing slash)
    ns = ns.replaceAll(new RegExp(`(?:/|^)${escapeRegExp(lookup)}(?=/)`, 'g'), '');
  }

  const folders = ns.split('/');
  const scope = findLast(folders, folder => folder.startsWith('@'));

  // Cleanup `ns` from unwanted parts and then normalize slashes to `:`
  ns = ns
    .replaceAll('//', '') // Remove double `/`
    .replace(/(.*generator-)/, '') // Remove before `generator-`
    .replace(/\/(index|main)$/, '') // Remove `/index` or `/main`
    .replace(/^\//, '') // Remove leading `/`
    .replaceAll(/\/+/g, ':'); // Replace slashes by `:`

  if (scope) {
    ns = `${scope}/${ns}`;
  }

  return ns;
};
