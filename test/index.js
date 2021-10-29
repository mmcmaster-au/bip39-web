var bip39 = require('../')
var download = require('../util/wordlists').download
var WORDLISTS = {
  english: require('../src/wordlists/english.json'),
  japanese: require('../src/wordlists/japanese.json'),
  custom: require('./wordlist.json')
}

var vectors = require('./vectors.json')
var test = require('tape')

function testVector (description, wordlist, password, v, i) {
  var ventropy = v[0]
  var vmnemonic = v[1]
  var vseedHex = v[2]

  test('for ' + description + '(' + i + '), ' + ventropy, function (t) {
    t.plan(5)

    const fn = async () => {
      t.equal(await bip39.mnemonicToEntropyAsync(vmnemonic, wordlist), ventropy, 'mnemonicToEntropy returns ' + ventropy.slice(0, 40) + '...')
      t.equal((await bip39.mnemonicToSeedAsync(vmnemonic, password)).toString('hex'), vseedHex, 'mnemonicToSeedAsync returns ' + vseedHex.slice(0, 40) + '...')
      t.equal(await bip39.entropyToMnemonicAsync(ventropy, wordlist), vmnemonic, 'entropyToMnemonicAsync returns ' + vmnemonic.slice(0, 40) + '...')

      function rng () { return Buffer.from(ventropy, 'hex') }
      t.equal(await bip39.generateMnemonicAsync(undefined, rng, wordlist), vmnemonic, 'generateMnemonicAsync returns RNG entropy unmodified')
      t.equal(await bip39.validateMnemonicAsync(vmnemonic, wordlist), true, 'validateMnemonicAsync returns true')
    };
    fn();
  })
}

vectors.english.forEach(function (v, i) { testVector('English', undefined, 'TREZOR', v, i) })
vectors.japanese.forEach(function (v, i) { testVector('Japanese', WORDLISTS.japanese, '㍍ガバヴァぱばぐゞちぢ十人十色', v, i) })
vectors.custom.forEach(function (v, i) { testVector('Custom', WORDLISTS.custom, undefined, v, i) })

test('getDefaultWordlist returns "english"', function (t) {
  t.plan(1)
  const english = bip39.getDefaultWordlist()
  t.equal(english, 'english')
  // TODO: Test that Error throws when called if no wordlists are compiled with bip39
})

test('setDefaultWordlist changes default wordlist', async function (t) {
  t.plan(4)
  const english = bip39.getDefaultWordlist()
  t.equal(english, 'english')

  bip39.setDefaultWordlist('italian')

  const italian = bip39.getDefaultWordlist()
  t.equal(italian, 'italian')

  const phraseItalian = await bip39.entropyToMnemonicAsync('00000000000000000000000000000000')
  t.equal(phraseItalian.slice(0, 5), 'abaco')

  bip39.setDefaultWordlist('english')

  const phraseEnglish = await bip39.entropyToMnemonicAsync('00000000000000000000000000000000')
  t.equal(phraseEnglish.slice(0, 7), 'abandon')
})

test('setDefaultWordlist throws on unknown wordlist', function (t) {
  t.plan(2)
  const english = bip39.getDefaultWordlist()
  t.equal(english, 'english')

  try {
    bip39.setDefaultWordlist('abcdefghijklmnop')
  } catch (error) {
    t.equal(error.message, 'Could not find wordlist for language "abcdefghijklmnop"')
    return
  }
  t.assert(false)
})

test('invalid entropy', async function (t) {
  t.plan(3)

  try {
      await bip39.entropyToMnemonicAsync(Buffer.from('', 'hex'));
      t.fail('throws for empty entropy');
  } catch (err) {
    t.equal(err.message, 'Invalid entropy', 'throws for empty entropy');
  }

  try {
    await bip39.entropyToMnemonicAsync(Buffer.from('000000', 'hex'));
    t.fail('throws for entropy that\'s not a multitude of 4 bytes');
  } catch (err) {
    t.equal(err.message, 'Invalid entropy', 'throws for entropy that\'s not a multitude of 4 bytes');
  }

  try {
    await bip39.entropyToMnemonicAsync(Buffer.from(new Array(1028 + 1).join('00'), 'hex'));
    t.fail('throws for entropy that is larger than 1024');
  } catch (err) {
    t.equal(err.message, 'Invalid entropy', 'throws for entropy that is larger than 1024');
  }
})

test('UTF8 passwords', function (t) {
  t.plan(vectors.japanese.length * 2)

  vectors.japanese.forEach(async function (v) {
    var vmnemonic = v[1]
    var vseedHex = v[2]

    var password = '㍍ガバヴァぱばぐゞちぢ十人十色'
    var normalizedPassword = 'メートルガバヴァぱばぐゞちぢ十人十色'

    t.equal((await bip39.mnemonicToSeedAsync(vmnemonic, password)).toString('hex'), vseedHex, 'mnemonicToSeedSync normalizes passwords')
    t.equal((await bip39.mnemonicToSeedAsync(vmnemonic, normalizedPassword)).toString('hex'), vseedHex, 'mnemonicToSeedSync leaves normalizes passwords as-is')
  })
})

test('generateMnemonic can vary entropy length', async function (t) {
  var words = (await bip39.generateMnemonicAsync(160)).split(' ')

  t.plan(1)
  t.equal(words.length, 15, 'can vary generated entropy bit length')
})

test('generateMnemonic requests the exact amount of data from an RNG', async function (t) {
  t.plan(1)

  await bip39.generateMnemonicAsync(160, function (size) {
    t.equal(size, 160 / 8)
    return Buffer.allocUnsafe(size)
  })
})

test('validateMnemonic', async function (t) {
  t.plan(5)

  t.equal(await bip39.validateMnemonicAsync('sleep kitten'), false, 'fails for a mnemonic that is too short')
  t.equal(await bip39.validateMnemonicAsync('sleep kitten sleep kitten sleep kitten'), false, 'fails for a mnemonic that is too short')
  t.equal(await bip39.validateMnemonicAsync('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about end grace oxygen maze bright face loan ticket trial leg cruel lizard bread worry reject journey perfect chef section caught neither install industry'), false, 'fails for a mnemonic that is too long')
  t.equal(await bip39.validateMnemonicAsync('turtle front uncle idea crush write shrug there lottery flower risky shell'), false, 'fails if mnemonic words are not in the word list')
  t.equal(await bip39.validateMnemonicAsync('sleep kitten sleep kitten sleep kitten sleep kitten sleep kitten sleep kitten'), false, 'fails for invalid checksum')
})

test('exposes standard wordlists', function (t) {
  t.plan(2)
  t.same(bip39.wordlists.EN, WORDLISTS.english)
  t.equal(bip39.wordlists.EN.length, 2048)
})

test('verify wordlists from https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md', function (t) {
  download().then(function (wordlists) {
    Object.keys(wordlists).forEach(function (name) {
      t.same(bip39.wordlists[name], wordlists[name])
    })

    t.end()
  })
})
