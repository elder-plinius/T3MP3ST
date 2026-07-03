import { execaSync } from 'execa';

export const execaOutput = (cmg: string, arguments_: string[]): string | undefined => {
  try {
    const { failed, stdout } = execaSync(cmg, arguments_, { encoding: 'utf8' });
    if (!failed) {
      return stdout;
    }
  } catch {
    // ignore error
  }

  return;
};

/**
 * Two-step argument splitting function that first splits arguments in quotes,
 * and then splits up the remaining arguments if they are not part of a quote.
 */
export function splitArgsFromString(argumentsString: string | string[]): string[] {
  if (Array.isArray(argumentsString)) {
    return argumentsString;
  }

  let result: string[] = [];
  if (!argumentsString) {
    return result;
  }

  const quoteSeparatedArguments = argumentsString.split(/("[^"]*")/).filter(Boolean);
  for (const argument of quoteSeparatedArguments) {
    if (argument.includes('"')) {
      result.push(argument.replaceAll('"', ''));
    } else {
      result = result.concat(argument.trim().split(' '));
    }
  }

  return result;
}
