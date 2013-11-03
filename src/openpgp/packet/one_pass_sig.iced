
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
hash = require '../../hash'
{uint_to_buffer} = require '../../util'

#=================================================================================

# 5.4. One-Pass Signature Packets (Tag 4)
class OnePassSignature extends Packet

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

  #---------------

  write : (cb) ->
    await @write_unframed defer err, unframed
    framed = @frame_packet C.packet_tags.one_pass_sig, unframed
    cb err, framed

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
