kbpgp = require '../..'
C = kbpgp.const.openpgp
{unbox,box,KeyManager} = kbpgp
{ECDSA} = kbpgp.ecc

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
  await unbox { keyfetch : km, armored : ciphertext  }, T.esc(defer(plaintext), cb)
  T.equal msg, plaintext[0].data.toString('utf8'), "right plaintext back out"
  km.pgp.subkeys = [ km.pgp.subkeys[2] ]
  await unbox { keyfetch : km, armored : ciphertext  }, T.esc(defer(plaintext), cb)
  T.equal msg, plaintext[0].data.toString('utf8'), "right plaintext back out"

  km.pgp.subkeys = []
  await unbox { keyfetch : km, armored : ciphertext  }, defer err
  T.assert err?, "error came back with no keys"
  T.assert err.toString().indexOf("No keys match the given key IDs") >= 0, "the right error msg"
  cb()
