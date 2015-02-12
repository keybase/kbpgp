
{KeyManager} = require '../../'
{PgpKeyRing} = require '../../lib/keyring'
{do_message } = require '../../lib/openpgp/processor'

#==================================================================================================

# Compressed with bzip2
msgs = [ """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

owNCWmg2MUFZJlNZhNKFqQAAa3///7fTt0s18FriG7/332/987/n+e5//n6y6Ov8
qPf/cycwAPssHCaANDJoANA0bUNDQDQAAAAAZA0AAaA9RpkDQNAZA0aaB4mFPJPE
KqBkAyaaADQaaNABiAyAaaMjRkMjIxDQ00xNBkAyGm1Ghpp6RpkZDIyGhoPSFVP1
TNT0hoMIAaNBoADRpkMgyAHpGgAGTTBGIGQ0aAD1NDQNMQyA0aGmgAjBiDjYyEXH
Fd9vIWBEBNmP4BY2Tk4UmwihAZwKIxTAXfpASdfkrzZQyx73ZXUMiJ4L9eP21jfl
nS3mmUaUSmeyBt2BPOAvCBHZOhB4asYItgeuAb3RlP3/iLktAWZlCIL1QnAQaBPD
M6Dm/ZZFN/Iev4DWoF0nJZgG+mdaQFSkBDhuWd2qCVaEq8flxS+u5abW9lj777Ms
CIIuN1OEuI+ga6CfseccLZrIDOvEKBAG1bWMuedWTOtG5egRrrSBgPVCuGRTQXch
jiJdxOIsfj5l5OaJiNb90oS+be5bJhChnrwf0YO2jZkiFBrR/pyHgDHVuguTtAkk
/SMVf8pyKovyDZSr2xSKqaAcilmiqTyYEXFI7UX/NDlpekK7JKANIAIMCQG4903X
pwCzGxtrHxxx2LuSKcKEhCaULUg=
=Qpgh
-----END PGP MESSAGE-----
""", """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

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
=5BXD
-----END PGP MESSAGE-----
"""
]

#==================================================================================================

texts = [
  """This text is compressed with bzip2\n"""
  """The old South Boston Aquarium stands in a Sahara of snow now. Its broken windows are boarded. The bronze weathervane cod has lost half its scales. The airy tanks are dry. Once my nose crawled like a snail on the glass; my hand tingled to burst the bubbles drifting from the noses of the cowed, compliant fish. My hand draws back. I often sigh still for the dark downward and vegetating kingdom of the fish and reptile. One morning last March, I pressed against the new barbed and galvanized fence on the Boston Common. Behind their cage, yellow dinosaur steamshovels were grunting as they cropped up tons of mush and grass to gouge their underworld garage. Parking spaces luxuriate like civic sandpiles in the heart of Boston. A girdle of orange, Puritan-pumpkin colored girders braces the tingling Statehouse, shaking over the excavations, as it faces Colonel Shaw and his bell-cheeked Negro infantry on St. Gaudens' shaking Civil War relief, propped by a plank splint against the garage's earthquake. Two months after marching through Boston, half the regiment was dead; at the dedication, William James could almost hear the bronze Negroes breathe. Their monument sticks like a fishbone in the city's throat. Its Colonel is as lean as a compass-needle. He has an angry wrenlike vigilance, a greyhound's gentle tautness; he seems to wince at pleasure, and suffocate for privacy. He is out of bounds now. He rejoices in man's lovely, peculiar power to choose life and die-- when he leads his black soldiers to death, he cannot bend his back. On a thousand small town New England greens, the old white churches hold their air of sparse, sincere rebellion; frayed flags quilt the graveyards of the Grand Army of the Republic. The stone statues of the abstract Union Soldier grow slimmer and younger each year-- wasp-waisted, they doze over muskets and muse through their sideburns . . . Shaw's father wanted no monument except the ditch, where his son's body was thrown and lost with his "niggers." The ditch is nearer. There are no statues for the last war here; on Boylston Street, a commercial photograph shows Hiroshima boiling over a Mosler Safe, the "Rock of Ages" that survived the blast. Space is nearer. When I crouch to my television set, the drained faces of Negro school-children rise like balloons. Colonel Shaw is riding on his bubble, he waits for the blessèd break. The Aquarium is gone. Everywhere, giant finned cars nose forward like fish; a savage servility slides by on grease."""
]


#==================================================================================================

key = require("../data/keys.iced").keys.mk

#==================================================================================================

exports.process = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, km
  T.no_error err
  ring = new PgpKeyRing()
  ring.add_key_manager km
  for msg,i in msgs
    await do_message { keyfetch : ring, armored : msg }, defer err, literals
    T.no_error err
    T.equal literals[0].data.toString('utf8'), texts[i]
    T.waypoint "msg #{i} checked out!"
  cb()

#==================================================================================================
