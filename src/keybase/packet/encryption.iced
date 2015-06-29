
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

  constructor : ({@encrypt_for, @sign_with, @plaintext, @ciphertext, @sender_key, @nonce, @anonymous}) ->
    super()
    @ephemeral = false

  #------------------

  get_packet_body : () ->
    enc_type = Encryption.ENC_TYPE
    { @sender_key, @ciphertext, @nonce, enc_type, @receiver_key }

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

  get_sender_keypair : ({sign_with,encrypt}, cb) ->
    err = ret = null
    if sign_with? then ret = sign_with.get_keypair()
    else if @sign_with? then ret = @sign_with.get_keypair()
    else if @sender_keypair? then ret = @sender_keypair
    else if encrypt
      await dh.Pair.generate {}, defer err, @sender_keypair
      ret = @sender_keypair
      @ephemeral = true
    else if @sender_key?
      [err, @sender_keypair] = dh.Pair.parse_kb @sender_key
      unless err?
        ret = @sender_keypair
    else
      err = new Error "Cannot encrypt without a sender keypair"
    cb err, ret

  #------------------

  encrypt : (params, cb) ->
    esc = make_esc cb, "encrypt"
    await @get_sender_keypair {encrypt : true }, esc defer sender
    recvr = @encrypt_for.get_keypair()
    await recvr.encrypt_kb { @plaintext, sender }, esc defer { @ciphertext, @nonce }
    @sender_key = sender.ekid() unless @anonymous and not @ephemeral
    @receiver_key = recvr.ekid() unless @anonymous
    cb null

  #------------------

  decrypt : ({sign_with, encrypt_for}, cb) ->
    esc = make_esc cb, "decrypt"
    await @get_sender_keypair {sign_with}, esc defer sender
    args = { @ciphertext, @nonce, sender }
    recvr = encrypt_for.get_keypair()
    await recvr.decrypt_kb args, esc defer @plaintext
    cb null, { sender_keypair : sender, @plaintext, receiver_keypair : recvr }

  #------------------

  unbox : ({encrypt_for}, cb) ->
    await @decrypt {encrypt_for}, defer err, res
    cb err, res

  #------------------

  @box : ({sign_with, encrypt_for, plaintext, anonymous}, cb) ->
    packet = new Encryption { sign_with, encrypt_for, plaintext, anonymous } 
    await packet.encrypt {}, defer err
    packet = null if err?
    cb err, packet

#=================================================================================

exports.Encryption = Encryption
