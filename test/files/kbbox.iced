top = require '../../'
{kb} = top
{make_esc} = require 'iced-error'
{SRF} = require '../../lib/rand'
{unpack} = require 'purepack'
{bufeq_fast} = top.util

exports.box_unbox_with_nonce = (T,cb) ->
  esc = make_esc cb, "box_unbox_with_nonce"
  await kb.EncKeyManager.generate {}, esc defer km
  await SRF().random_bytes 24, defer nonce
  msg = new Buffer "hello world", "utf8"
  await kb.box { encrypt_for : km, nonce, msg }, esc defer armored
  unpacked = unpack new Buffer armored, 'base64'
  T.assert bufeq_fast(unpacked.body.nonce, nonce), "used the right nonce"
  await kb.unbox { armored, encrypt_for : km }, esc defer msg2
  T.assert bufeq_fast(msg, msg2.plaintext), "message came back out"

  await SRF().random_bytes 23, defer nonce
  await kb.box { encrypt_for : km, nonce, msg }, defer err
  T.assert err?, "fail to encrypt with bad nonce"

  cb()

