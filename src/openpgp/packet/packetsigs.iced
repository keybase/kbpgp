#
# Classes used to represent the verified signatures on packets.
# Only one a signature checks out do we go through and apply these
# packetsig objects onto the packets that they cover.
#
#===================================================

class Base
  constructor : ({@sig,@key_expiration}) ->
  typ : () -> "none"
  get_key_flags : () -> @sig.get_key_flags()
  push : (lookup) ->
    lookup[@typ()].push @

#===================================================

class SelfSig extends Base
  constructor : ({@userid, @user_attribute, @type, sig, @options, key_expiration, sig_expiration}) ->
    super { sig, key_expiration, sig_expiration}
  typ : () -> "self_sig"
  push : (lookup) ->
    lookup.self_sig.push @
    key = if @userid? then @userid.utf8() or ""
    unless (v = lookup.self_sigs_by_uid[key])?
      v = []
      lookup.self_sigs_by_uid[key] = v
    v.push @

#===================================================

class SubkeyBinding extends Base
  @UP   : 1
  @DOWN : 2
  constructor : ({@primary, sig, @direction, sig_expiration, key_expiration}) ->
    super { sig, key_expiration, sig_expiration }
  typ : () -> "subkey_binding"
  is_down : () -> (@direction is SubkeyBinding.DOWN)

#===================================================

class Data extends Base
  constructor : ({@key, sig, key_expiration, sig_expiration}) ->
    super {sig, key_expiration, sig_expiration }
  typ : () -> "data"
  get_key_manager : () -> @sig?.key_manager

#===================================================

class Collection

  #-------------------

  constructor : () ->
    @clear()

  #-------------------

  clear : () ->
    @all             = []
    @lookup          =
      self_sig         : []
      self_sigs_by_uid : {}
      subkey_binding   : []
      data             : []

  #-------------------

  push : (ps) ->
    @all.push ps
    ps.push @lookup

  #-------------------

  #
  # See if this data packet has signatures saying that it's a signed subkey
  # of the given primary.  We're only checking that the primary has signed the
  # subkey (a **down**ward signature).  We're not checking the upward signature.
  #
  # See Issue #19 for further details...
  #
  is_signed_subkey_of : (primary, need_upwards_sig) ->
    up = down = false
    for skb in @lookup.subkey_binding
      if skb.primary.equal(primary)
        if skb.is_down() then down = true else up = true
        return true if down and (up or not need_upwards_sig)
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
  get_signed_user_attributes: () -> (u for p in @lookup.self_sig when (u = p.user_attribute)?)

  #-------------------

  get_self_sig : () -> if @lookup.self_sig.length then @lookup.self_sig[0] else null
  get_self_sigs : () -> @lookup.self_sig

  #-------------------

  # Was there at least one signed-self userid on the key?
  is_self_signed : () -> @get_signed_userids().length > 0

  #-------------------

  get_data_signer  : () -> if @lookup.data.length > 0 then @lookup.data[0] else null
  get_data_signers : () -> @lookup.data

  #-------------------

  get_subkey_binding : () -> if @lookup.subkey_binding.length then @lookup.subkey_binding[0] else null

#===================================================

exports.SelfSig = SelfSig
exports.SubkeyBinding = SubkeyBinding
exports.Data = Data
exports.Collection = Collection

#===================================================

