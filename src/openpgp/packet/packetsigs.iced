#
# Classes used to represent the verified signatures on packets.
# Only one a signature checks out do we go through and apply these
# packetsig objects onto the packets that they cover.
# 
#===================================================

class Base
  constructor : ({@sig}) ->
  typ : () -> "none"

#===================================================

class SelfSig extends Base
  constructor : ({@userid, @type, sig, @options}) -> super { sig }
  typ : () -> "self_sig"

#===================================================

class SubkeyBinding extends Base
  UP   : 1
  DOWN : 2
  constructor : ({@primary, sig, @direction}) -> super { sig }
  typ : () -> "subkey_binding"
  is_down : () -> (@direction is SubkeyBinding.DOWN)

#===================================================

class Data extends Base
  constructor : ({@key, sig}) -> super {sig}
  typ : () -> "data"

#===================================================

class Collection 

  #-------------------
  
  constructor : () ->
    @all             = []
    @lookup          = 
      self_sig       : []
      subkey_binding : []
      data           : []

  #-------------------

  push : (ps) ->
    @all.push ps
    @lookup[ps.typ()].push ps

  #-------------------

  #
  # See if this data packet has signatures saying that it's a signed subkey
  # of the given primary.  We're only checking that the primary has signed the
  # subkey (a **down**ward signature).  We're not checking the upward signature.
  #  
  # See Issue #19 for furthet details...
  #
  is_signed_subkey_of : (primary) ->
    for skb in @lookup.subkey_binding
      if skb.primary.equal(primary) and skb.is_down()
        return true
    return false

  #-------------------

  # Look through all signature packets, and OR together all of the key flags
  # promised their signed KeyFlags subpackets.
  get_all_key_flags : () ->
    ret = 0
    (ret |= p.get_key_flags() for p in @all)
    return ret

  #-------------------

  # Return all self-signed UID packets. Only useful for primary keys.
  get_signed_userids : () -> (u for p in @lookup.self_sig when (u = p.userid)?)

  #-------------------

  # Was there at least one signed-self userid on the key?
  is_self_signed : () -> @get_signed_userids().length > 0

  #-------------------

  get_data_signer  : () -> if @lookup.data.length > 0 then @lookup.data[0] else null
  get_data_signers : () -> @lookup.data

#===================================================

exports.SelfSig = SelfSig
exports.SubkeyBinding = SubkeyBinding
exports.Data = Data
exports.Collection = Collection

#===================================================

