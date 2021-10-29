import { _default as _DEFAULT_WORDLIST, wordlists } from './_wordlists';

let DEFAULT_WORDLIST: string[] | undefined = _DEFAULT_WORDLIST;

const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
const INVALID_CHECKSUM = 'Invalid mnemonic checksum';
const WORDLIST_REQUIRED =
  'A wordlist is required but a default could not be found.\n' +
  'Please pass a 2048 word array explicitly.';

const webcrypto =
  typeof crypto !== 'undefined' ? crypto : require('crypto').webcrypto;

function normalize(str?: string): string {
  return (str || '').normalize('NFKD');
}

function lpad(str: string, padString: string, length: number): string {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
}

function binaryToByte(bin: string): number {
  return parseInt(bin, 2);
}

function bytesToBinary(bytes: number[]): string {
  return bytes.map((x: number): string => lpad(x.toString(2), '0', 8)).join('');
}

async function deriveChecksumBitsAsync(entropyBuffer: Buffer): Promise<string> {
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  const hash = await webcrypto.subtle.digest(
    'SHA-256',
    new Uint8Array(
      entropyBuffer.buffer,
      entropyBuffer.byteOffset,
      entropyBuffer.byteLength,
    ),
  );

  return bytesToBinary(Array.from(new Uint8Array(hash))).slice(0, CS);
}

function salt(password?: string): string {
  return 'mnemonic' + (password || '');
}

export async function mnemonicToSeedAsync(
  mnemonic: string,
  password?: string,
): Promise<Buffer> {
  const mnemonicBuffer = Buffer.from(normalize(mnemonic), 'utf8');
  const saltBuffer = Buffer.from(salt(normalize(password)), 'utf8');

  const key = await webcrypto.subtle.importKey(
    'raw',
    new Uint8Array(
      mnemonicBuffer.buffer,
      mnemonicBuffer.byteOffset,
      mnemonicBuffer.byteLength,
    ),
    'PBKDF2', // { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey'],
  );

  const seedBits = await webcrypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(
        saltBuffer.buffer,
        saltBuffer.byteOffset,
        saltBuffer.byteLength,
      ),
      iterations: 2048,
      hash: 'SHA-512',
    },
    key,
    512,
  );

  return Buffer.from(seedBits);
}

export async function mnemonicToEntropyAsync(
  mnemonic: string,
  wordlist?: string[],
): Promise<string> {
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  const words = normalize(mnemonic).split(' ');
  if (words.length % 3 !== 0) {
    throw new Error(INVALID_MNEMONIC);
  }

  // convert word indices to 11 bit binary strings
  const bits = words
    .map(
      (word: string): string => {
        const index = wordlist!.indexOf(word);
        if (index === -1) {
          throw new Error(INVALID_MNEMONIC);
        }

        return lpad(index.toString(2), '0', 11);
      },
    )
    .join('');

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g)!.map(binaryToByte);
  if (entropyBytes.length < 16) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length > 32) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length % 4 !== 0) {
    throw new Error(INVALID_ENTROPY);
  }

  const entropy = Buffer.from(entropyBytes);
  const newChecksum = await deriveChecksumBitsAsync(entropy);
  if (newChecksum !== checksumBits) {
    console.log(entropy.toString('hex'));

    console.log('Expected ' + checksumBits + ' actual: ' + newChecksum);
    throw new Error(INVALID_CHECKSUM);
  }

  return entropy.toString('hex');
}

export async function entropyToMnemonicAsync(
  entropy: Buffer | string,
  wordlist?: string[],
): Promise<string> {
  if (!Buffer.isBuffer(entropy)) {
    entropy = Buffer.from(entropy, 'hex');
  }
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  // 128 <= ENT <= 256
  if (entropy.length < 16) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length > 32) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length % 4 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }

  const entropyBits = bytesToBinary(Array.from(entropy));
  const checksumBits = await deriveChecksumBitsAsync(entropy);

  const bits = entropyBits + checksumBits;
  const chunks = bits.match(/(.{1,11})/g)!;
  const words = chunks.map(
    (binary: string): string => {
      const index = binaryToByte(binary);
      return wordlist![index];
    },
  );

  return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
    ? words.join('\u3000')
    : words.join(' ');
}

export async function generateMnemonicAsync(
  strength?: number,
  rng?: (size: number) => Buffer,
  wordlist?: string[],
): Promise<string> {
  strength = strength || 128;
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }

  if (!rng) {
    rng = (size: number): Buffer => {
      const rngValues = new Uint8Array(size);
      webcrypto.getRandomValues(rngValues);
      return Buffer.from(rngValues);
    };
  }

  return entropyToMnemonicAsync(rng(strength / 8), wordlist);
}

export async function validateMnemonicAsync(
  mnemonic: string,
  wordlist?: string[],
): Promise<boolean> {
  try {
    await mnemonicToEntropyAsync(mnemonic, wordlist);
  } catch (e) {
    return false;
  }

  return true;
}

export function setDefaultWordlist(language: string): void {
  const result = wordlists[language];
  if (result) {
    DEFAULT_WORDLIST = result;
  } else {
    throw new Error('Could not find wordlist for language "' + language + '"');
  }
}

export function getDefaultWordlist(): string {
  if (!DEFAULT_WORDLIST) {
    throw new Error('No Default Wordlist set');
  }
  return Object.keys(wordlists).filter(
    (lang: string): boolean => {
      if (lang === 'JA' || lang === 'EN') {
        return false;
      }
      return wordlists[lang].every(
        (word: string, index: number): boolean =>
          word === DEFAULT_WORDLIST![index],
      );
    },
  )[0];
}

export { wordlists } from './_wordlists';
