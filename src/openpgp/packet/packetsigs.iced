#
# Classes used to represent the verified signatures on packets.
# Only one a signature checks out do we go through and apply these
# packetsig objects onto the packets that they cover.
# 
#===================================================

class Base
  constructor : ({@sig}) ->
  type : () -> "none"

#===================================================

class SelfSig extends Base
  constructor : ({@userid, @type, sig, @options}) ->
    super { sig }
    type : () -> "self_sig"

#===================================================

class SubkeyBinding extends Base
  @DIRECTIONS = [ UP, DOWN ]
  constructor : ({@primary, sig, @direction}) ->
    super { sig }
    type : () -> "subkey_binding"

#===================================================

class Data extends Base
  constructor : ({@key, sig}) ->
    super {sig}
    type : () -> "data"

#===================================================

class Collection 

  constructor : () ->
    @all             = []
    @lookup          = 
      self_sig       : []
      subkey_binding : []
      data           : []

  push : (ps) ->
    @all.push ps
    @lookup[ps.type()].push ps

#===================================================

exports.SelfSig = SelfSig
exports.SubkeyBinding = SubkeyBinding
exports.Data = Data
exports.Collection = Collection

#===================================================

