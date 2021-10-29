/// <reference types="node" />
export declare function mnemonicToSeedAsync(mnemonic: string, password?: string): Promise<Buffer>;
export declare function mnemonicToEntropyAsync(mnemonic: string, wordlist?: string[]): Promise<string>;
export declare function entropyToMnemonicAsync(entropy: Buffer | string, wordlist?: string[]): Promise<string>;
export declare function generateMnemonicAsync(strength?: number, rng?: (size: number) => Buffer, wordlist?: string[]): Promise<string>;
export declare function validateMnemonicAsync(mnemonic: string, wordlist?: string[]): Promise<boolean>;
export declare function setDefaultWordlist(language: string): void;
export declare function getDefaultWordlist(): string;
export { wordlists } from './_wordlists';
