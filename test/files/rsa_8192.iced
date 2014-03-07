{keys} = require '../data/keys.iced'
{parse} = require '../../lib/openpgp/parser'
armor = require '../../lib/openpgp/armor'
C = require '../../lib/const'
{do_message,Message} = require '../../lib/openpgp/processor'
util = require 'util'
{unix_time,katch,ASP} = require '../../lib/util'
{KeyManager} = require '../../lib/keymanager'
{import_key_pgp} = require '../../lib/symmetric'
{decrypt} = require '../../lib/openpgp/ocfb'
{PgpKeyRing} = require '../../lib/keyring'
{Literal} = require '../../lib/openpgp/packet/literal'
{burn} = require '../../lib/openpgp/burner'
clearsign = require '../../lib/openpgp/clearsign'

ring = null
km = null

#============================================================================

exports.import_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : keys.tinfoil }, defer err, tmp
  km = tmp
  ring = new PgpKeyRing()
  ring.add_key_manager km
  T.no_error err
  cb()

#============================================================================

msg = """
I wonder by my troth, what thou and I
Did, till we loved ? were we not weaned till then?
But sucked on country pleasures, childishly?
Or snorted we in the Seven Sleepers' den?
'Twas so ; but this, all pleasures fancies be;
If ever any beauty I did see,
Which I desired, and got, 'twas but a dream of thee.
"""

#============================================================================

exports.encrypt = (T, cb) ->
  flags = C.openpgp.key_flags.encrypt_comm
  encryption_key = km.find_best_pgp_key flags
  T.assert encryption_key?, "got an encryption key"
  literals = [ new Literal { 
    data : new Buffer(msg)
    format : C.openpgp.literal_formats.utf8 
    date : unix_time()
  }]
  await burn { literals, encryption_key }, defer err, armored, ctext
  T.no_error err
  cb()

#============================================================================

