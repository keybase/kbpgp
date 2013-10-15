
{Base} = require './base'
triplesec = require 'triplesec'

#=================================================================================

class BaseKey extends Base

  constructor : ({type, @keyring, @username}) ->
    super { type }

  make : ({tsec, passphrase }) ->
    tsec = new Triplesec { key : passphrase } unless tsec?
    @packets.push @keyring.master().to_packet()
    @packets.push new IssuerSig { key : @keyring.master, @username }
    for key in @keyring.subkeys()



#=================================================================================
