/**
 * Tiny console logger. No dependencies.
 */

export interface Logger {
  info: (msg: string, ...args: unknown[]) => void;
  warn: (msg: string, ...args: unknown[]) => void;
  error: (msg: string, ...args: unknown[]) => void;
  debug: (msg: string, ...args: unknown[]) => void;
}

export function createLogger(scope: string): Logger {
  const tag = `[${scope}]`;
  return {
    info: (msg, ...args) => console.error(`${tag} ${msg}`, ...args),
    warn: (msg, ...args) => console.error(`${tag} WARN ${msg}`, ...args),
    error: (msg, ...args) => console.error(`${tag} ERROR ${msg}`, ...args),
    debug: (msg, ...args) => {
      if (process.env.APP2API_DEBUG) console.error(`${tag} DEBUG ${msg}`, ...args);
    },
  };
}
