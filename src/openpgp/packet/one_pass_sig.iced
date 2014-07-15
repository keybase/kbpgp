
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
hash = require '../../hash'
{uint_to_buffer} = require '../../util'
{InitableTransform} = require '../../stream'

#=================================================================================

# 5.4. One-Pass Signature Packets (Tag 4)
class OnePassSignature extends Packet

  @TAG : C.packet_tags.one_pass_sig
  TAG : OnePassSignature.TAG

  #---------------

  constructor : ( {@sig_type, @hasher, @sig_klass, @key_id, @is_final }) ->

  #---------------

  @parse : (slice) -> (new OPS_Parser slice).parse()

  #---------------

  write_unframed : (cb) ->
    vals = [
      C.versions.one_pass_sig, 
      @sig_type,
      @hasher.type,
      @sig_klass.type
    ]
    bufs = (uint_to_buffer(8,x) for x in vals)
    bufs.push @key_id
    bufs.push uint_to_buffer(8,@is_final)
    unframed = Buffer.concat bufs
    cb null, unframed

#=================================================================================

class OPS_Parser 

  constructor : (@slice) ->

  #  The body of this packet consists of:
  #
  #   - A one-octet version number.  The only currently defined value is 1.
  #   - Encrypted data, the output of the selected symmetric-key cipher
  #     operating in Cipher Feedback mode with shift amount equal to the
  #     block size of the cipher (CFB-n where n is the block size).
  parse : () -> 
    unless (v = @slice.read_uint8()) is C.versions.one_pass_sig
      throw new Error "Unknown OnePassSignature version #{v}"
    sig_type = @slice.read_uint8()
    hasher = hash.alloc_or_throw @slice.read_uint8()
    sig_klass = asymmetric.get_class @slice.read_uint8() 
    key_id = @slice.read_buffer 8
    is_final = @slice.read_uint8()
    new OnePassSignature { sig_type, hasher, sig_klass, key_id, is_final }

#=================================================================================

exports.OnePassSignature = OnePassSignature

#=================================================================================

exports.OutStream = class OutStream extends InitableTransform

  constructor : ({@header, @footer, literal}) ->
    super()
    @_literal_stream = new literal.OutStream { packet : literal }
    @_literal_stream.on 'data', (data) -> @push data
    @_literal_stream.on 'error', (err) -> @emit 'error', err

  _v_init : (cb) ->
    # Push out the "OnePassSignature" header packet
    await @header.write defer err, buf
    @push buf unless err?
    cb err

  _v_transform : (data, encoding, cb) ->
    @hasher.update data
    await @_literal_stream.write data, defer()
    cb null

  _v_flush : (cb) ->
    await @_literal_stream.end defer()
    await @footer.write defer err, buf
    @push buf unless err?
    cb err

#=================================================================================
