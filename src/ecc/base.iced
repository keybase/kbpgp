{SlicerBuffer} = require '../openpgp/buffer'
{alloc_by_oid} = require './curves'

#===========================================================================

exports.BaseEccKey = class BaseEccKey

  #----------------

  constructor : ({@curve, @R}) ->

  #----------------

  serialize : () ->
    oid = @curve.oid
    Buffer.concat [
      new Buffer([ oid.length ]),
      oid,
      @curve.point_to_mpi_buffer(@R)
    ]

  #----------------

  @_alloc : (klass, raw) ->
    sb = new SlicerBuffer raw
    pre = sb.rem()
    l = sb.read_uint8()
    oid = sb.read_buffer(l)
    [err, curve] = alloc_by_oid oid
    throw err if err?
    [err, R] = curve.mpi_point_from_slicer_buffer sb
    throw err if err?
    pub = new klass { curve, R}
    pub.read_params sb
    len = pre - sb.rem()
    return [ pub, len ]

  #----------------

  @alloc : (klass, raw) ->
    pub = len = err = null
    try [pub, len] = BaseEccKey._alloc klass, raw
    catch e then err = e
    return [err, pub, len] 


#===========================================================================



