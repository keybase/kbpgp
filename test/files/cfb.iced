
{encrypt,decrypt} = require '../../lib/openpgp/cfb'

exports.nist_sp800_38a__f_3_17 = (T,cb) ->
  key = new Buffer "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 'hex'
  iv = new Buffer "000102030405060708090a0b0c0d0e0f", "hex"
  pt_raw = [ "6bc1bee22e409f96e93d7e117393172a",
             "ae2d8a571e03ac9c9eb76fac45af8e51",
             "30c81c46a35ce411e5fbc1191a0a52ef",
             "f69f2445df4f9b17ad2b417be66c3710" ]
  ct_raw = [ "dc7e84bfda79164b7ecd8486985d3860",
             "39ffed143b28b1c832113c6331e5407b",
             "df10132415e54b92a13ed0a8267ae2f9",
             "75a385741ab9cef82031623d55b1e471"
  ]

  test = (T, n, pt, ct) ->
    plaintext = Buffer.concat(new Buffer(p, 'hex') for p in pt)
    len = plaintext.length - n
    plaintext = plaintext[0...len]
    ciphertext = Buffer.concat(new Buffer(c, 'hex') for c in ct)
    ciphertext = ciphertext[0...len]

    ct_ours = encrypt {key, plaintext, iv}
    T.equal ct_ours.toString(), ciphertext.toString(), "encryption produced expected result (trunc=#{n})"
    pt2 = decrypt { key, ciphertext, iv }
    T.equal pt2.toString(), plaintext.toString(), "decryption produced expected result (trunc=#{n})"

  # test all various truncations....
  for i in [0...16] 
    test T, i, pt_raw, ct_raw

  cb()

