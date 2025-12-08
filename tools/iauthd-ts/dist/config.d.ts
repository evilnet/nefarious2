/**
 * Configuration parser for iauthd
 * Reads #IAUTH directives from config files
 */
import type { Config } from './types.js';
/**
 * Read and parse configuration from a file
 * Looks for lines starting with #IAUTH
 */
export declare function readConfigFile(filePath: string): {
    config: Config;
    configLines: string[];
};
//# sourceMappingURL=config.d.ts.map