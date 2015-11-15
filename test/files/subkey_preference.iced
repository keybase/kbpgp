kbpgp = require '../..'
C = kbpgp.const.openpgp
{unbox,box,KeyManager} = kbpgp
{ECDSA} = kbpgp.ecc
{unix_time} = kbpgp.util

exports.test_multiple_encryption_subkeys = (T,cb) ->
  F = C.key_flags
  primary = {
    flags : F.certify_keys
    nbits : 384
    algo : ECDSA
  }
  subkeys = [{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 100
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 2000
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 5000
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 50
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 10
  }]
  userid = "Tester 1 <tester@gmail.com>"
  await KeyManager.generate { userid, primary, subkeys }, T.esc(defer(km), cb)
  await km.sign {}, T.esc(defer())

  msg = "Huffy Henry hid the day, unappeasable Henry sulked."
  await box { encrypt_for : km, msg  }, T.esc(defer(ciphertext), cb)

  # Decrypt as normal should work
  await unbox { keyfetch : km, armored : ciphertext  }, T.esc(defer(plaintext), cb)
  T.equal msg, plaintext[0].data.toString('utf8'), "right plaintext back out"
  km.pgp.subkeys = [ km.pgp.subkeys[2] ]

  # Decrypt with only the expected subkey should work
  await unbox { keyfetch : km, armored : ciphertext  }, T.esc(defer(plaintext), cb)
  T.equal msg, plaintext[0].data.toString('utf8'), "right plaintext back out"

  # Decrypt without any subkeys should work
  km.pgp.subkeys = []
  await unbox { keyfetch : km, armored : ciphertext  }, defer err
  T.assert err?, "error came back with no keys"
  T.assert err.toString().indexOf("No keys match the given key IDs") >= 0, "the right error msg"
  cb()

exports.test_multiple_encryption_subkeys_winner_did_not_expire = (T,cb) ->
  F = C.key_flags
  primary = {
    flags : F.certify_keys
    nbits : 384
    algo : ECDSA
  }
  subkeys = [{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 100
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 2000
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : null
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 50
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : 10
  }]
  userid = "Tester 1 <tester@gmail.com>"
  await KeyManager.generate { userid, primary, subkeys }, T.esc(defer(km), cb)
  await km.sign {}, T.esc(defer())

  msg = "Huffy Henry hid the day, unappeasable Henry sulked."
  await box { encrypt_for : km, msg  }, T.esc(defer(ciphertext), cb)

  # Decrypt as normal should work
  await unbox { keyfetch : km, armored : ciphertext  }, T.esc(defer(plaintext), cb)
  T.equal msg, plaintext[0].data.toString('utf8'), "right plaintext back out"
  km.pgp.subkeys = [ km.pgp.subkeys[2] ]

  # Decrypt with only the expected subkey should work
  await unbox { keyfetch : km, armored : ciphertext  }, T.esc(defer(plaintext), cb)
  T.equal msg, plaintext[0].data.toString('utf8'), "right plaintext back out"

  # Decrypt without any subkeys should work
  km.pgp.subkeys = []
  await unbox { keyfetch : km, armored : ciphertext  }, defer err
  T.assert err?, "error came back with no keys"
  T.assert err.toString().indexOf("No keys match the given key IDs") >= 0, "the right error msg"
  cb()

exports.test_multiple_encryption_subkeys_winner_latest = (T,cb) ->
  F = C.key_flags
  primary = {
    flags : F.certify_keys
    nbits : 384
    algo : ECDSA
  }

  when_gen = unix_time()
  expire_in = 999
  when_gen_0 = when_gen - 1000
  expire_in_0 = expire_in + 1000

  subkeys = [{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : expire_in_0
    generated : when_gen_0
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : expire_in_0
    generated : when_gen_0
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : expire_in
    generated : when_gen
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : expire_in_0
    generated : when_gen_0
  },{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 256
    expire_in : expire_in_0
    generated : when_gen_0
  }]
  userid = "Tester 1 <tester@gmail.com>"
  await KeyManager.generate { userid, primary, subkeys }, T.esc(defer(km), cb)
  await km.sign {}, T.esc(defer())

  msg = "Huffy Henry hid the day, unappeasable Henry sulked."
  await box { encrypt_for : km, msg  }, T.esc(defer(ciphertext), cb)

  # Decrypt as normal should work
  await unbox { keyfetch : km, armored : ciphertext  }, T.esc(defer(plaintext), cb)
  T.equal msg, plaintext[0].data.toString('utf8'), "right plaintext back out"
  km.pgp.subkeys = [ km.pgp.subkeys[2] ]

  # Decrypt with only the expected subkey should work
  await unbox { keyfetch : km, armored : ciphertext  }, T.esc(defer(plaintext), cb)
  T.equal msg, plaintext[0].data.toString('utf8'), "right plaintext back out"

  # Decrypt without any subkeys should work
  km.pgp.subkeys = []
  await unbox { keyfetch : km, armored : ciphertext  }, defer err
  T.assert err?, "error came back with no keys"
  T.assert err.toString().indexOf("No keys match the given key IDs") >= 0, "the right error msg"
  cb()
