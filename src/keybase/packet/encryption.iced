
konst = require '../../const'
K = konst.kb
C = konst.openpgp
{Packet} = require './base'
{make_esc} = require 'iced-error'
{dh} = require '../../nacl/main'

#=================================================================================

class Encryption extends Packet

  @ENC_TYPE : K.public_key_algorithms.NACL_DH

  #------------------

  @tag : () -> K.packet_tags.encryption
  tag : () -> Encryption.tag()

  #------------------

  constructor : ({@encrypt_for, @sign_with, @plaintext, @ciphertext, @sender_key, @nonce}) ->
    super()
    @emphemeral = false

  #------------------

  get_packet_body : () ->
    enc_type = Signature.SIG_TYPE
    { @sender_key, @ciphertext, @nonce, enc_type }

  #------------------

  @alloc : ({tag,body}) ->
    ret = null
    err = if tag isnt Encryption.tag() then new Error "wrong tag found: #{tag}"
    else if (a = body.enc_type) isnt (b = Encryption.ENC_TYPE)
      err = new Error "Expected Curve25519 DH (type #{b}); got #{a}"
    else
      ret = new Encryption body
      null
    throw err if err?
    ret

  #------------------

  is_signature : () -> false

  #------------------

  get_sender_keypair : ({encrypt}, cb) ->
    err = ret = null
    if @sign_with? then ret = @sign_with.get_keypair()
    else if @sender_keypair? then ret = @sender_keypair
    else if encrypt
      await dh.Pair.generate {}, defer err, @sender_keypair
      ret = @sender_keypair
      @emphemeral = true
    else if @sender_key?
      [err, @sender_keypair] = dh.Pair.parse_kb @sender_key
      unless err?
        ret = @sender_keypair
    else
      err = new Error "Cannot encrypt without a sender keypair"
    cb err, ret

  #------------------

  encrypt : (cb) ->
    esc = make_esc cb, "encrypt"
    await @get_sender_keypair {encrypt : true }, esc defer sender
    recvr = @encrypt_for.get_keypair()
    plaintext = Buffer.concat [ 
      @plaintext,
      new Buffer([ if @emphemeral then 1 else 0 ]),
    ]
    await recvr.encrypt_kb { plaintext, sender }, esc defer { @ciphertext, @nonce }
    cb null

  #------------------

  decrypt : (cb) ->
    esc = make_esc cb, "decrypt"
    await @get_sender_keypair {}, esc defer sender
    args = { @ciphertext, @nonce, sender }
    recvr = @encrypt_for.get_keypair()
    await recvr.decrypt_kb args, esc defer plaintext
    @plaintext = plaintext[0...-1]
    @emphemeral = plaintext[-1...][0]
    cb err, { keypair : sender, @plaintext, @emphemeral }

  #------------------

  unbox : (cb) ->
    await @decrypt defer err, res
    cb err, res

  #------------------

  @box : ({sign_with, encrypt_for, plaintext}, cb) ->
    packet = new Encryption { sign_with, encrypt_for, plaintext } 
    await packet.encrypt defer err
    packet = null if err?
    cb err, packet

#=================================================================================

exports.Signature = Signature
exports.sign = Signature.sign
