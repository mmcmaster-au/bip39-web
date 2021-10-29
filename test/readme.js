const bip39 = require('../')
const Buffer = require('safe-buffer').Buffer
const proxyquire = require('proxyquire')
const test = require('tape')

test('README example 1', async function (t) {
  // defaults to BIP39 English word list
  const entropy = 'ffffffffffffffffffffffffffffffff'
  const mnemonic = await bip39.entropyToMnemonicAsync(entropy)

  t.plan(2)
  t.equal(mnemonic, 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong')

  // reversible
  t.equal(await bip39.mnemonicToEntropyAsync(mnemonic), entropy)
})

test('README example 2', async function (t) {
  const mnemonic = 'basket actual'
  const seed = await bip39.mnemonicToSeedAsync(mnemonic)

  t.plan(2)
  t.equal(seed.toString('hex'), '5cf2d4a8b0355e90295bdfc565a022a409af063d5365bb57bf74d9528f494bfa4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f')
  t.equal(await bip39.validateMnemonicAsync(mnemonic), false)
})
