{KeyManager} = require '../../'
{do_message,Processor} = require '../../lib/openpgp/processor'

#==================================================================

key = require('../data/keys.iced').keys.mk

#================================================================================

sigs = [
  {
    sig : """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

owEBSgG1/pANAwAJAZgKPw0B/gTfAcsaYgBTS9bpdGhpcyBpcyB3aXRoIFNIQTM4
NAqJARwEAAEJAAYFAlNL1ukACgkQmAo/DQH+BN+31Qf/Wz3ZNNmA8ptd6uSxb38K
F7dwO3Blt/GJ46bOm7kDZc1+kv3/lkJg1Gl7NDfEySfXAAIJXbPiZxALwMkuR5jj
Wgif9qJgKfwSeMdjTBKKLtlRprwee6unSgTQ8zL2Q1BUGlqThWyTGj3kUWnoIA1w
rnwFQL0SBSu8Fg7HKEIEc1hMoP3R0RvjVmkzmA80d5d8xK+j+qqAGTZY3uTsV7XJ
VLVd31euXaOXXs+/ZPF6bRmC2hf73WIdC7MjtUO4VHRgAEGCprtRbPAVE5aX9LDY
dPR6bmTn5B4yI7hFkZg+ga3uSBcU5ay7jd3sAUeI1g9rp4bg36RTAsdsCC+ikBtS
qw==
=ccex
-----END PGP MESSAGE-----
""",
    which : "SHA384"
  }, {
    sig : """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

owEBSgG1/pANAwALAZgKPw0B/gTfAcsaYgBTS9isdGhpcyBpcyB3aXRoIFNIQTIy
NAqJARwEAAELAAYFAlNL2KwACgkQmAo/DQH+BN/Nggf/cFQvzcTwZ6R4F9zxqkVV
kmSfgCpBqMoZlv5e4o/pcCnoNGxAqk6U1+BUSWyMuZO6q/0h4y9NeOZVqViGs6Ma
JwwCjnrzQOc8BJEzJjCDjDkxelOkLRY2NzyJzwP6RUPIvF0GMIVOZIvSnmrCMdAY
lcAmSlz9RPYcWSkaStONi/9H8t5Ecih54sPR9iD24/VBgxfR7VNKCyOR85pf1qnE
Vt5VhPor4vTR4JzxLqysi8Lk+ghi4mzmAG4iPeSQCgJk1IhaFIIdY/2KxSN5QZIH
vceDHXDE0fW3ekPLm8+n30kheTlcllG2YJUYYE2LSpLPq8WCn65E74Ixp1a8wxLn
6g==
=gxp2
-----END PGP MESSAGE-----
""",
    which : "SHA224"
  }, {
    sig : """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

owEBSgG1/pANAwAIAZgKPw0B/gTfAcsaYgBTS9pedGhpcyBpcyB3aXRoIFNIQTI1
NgqJARwEAAEIAAYFAlNL2l4ACgkQmAo/DQH+BN8SxAgAjuJmx3EraPjJ86g+C7Ma
jB0fovW2DsHKULdXiawzUiAPeBBP+gweReCnV9aIVgnxz5yDxxvQZKYxQ+0oD47f
hlUN4orhyI5Pbmq+uj7dDVuzwG53W1doNNeyJggO8OtEBlmXtMbDuf6J23adorij
hPRVkjLBKAmjz5ZN9TIznWcY12VMsbon9gJvzZ+8py7TlZlawxy02Q4/GnzvDje1
qx+sGKqNdwN+wqWU5K+T/ofbLfvAH2kfiKqoCYVMHutUgUC5x3tWPEdeZKgkCAa1
FhaSZ+DdsZJs77qAM0hIQfAP65F+8iJiBsRZ8XzD+wn2gZv7k8SR6WgbtvvDgJ6l
xg==
=jK3a
-----END PGP MESSAGE-----
""",
    which : "SHA256"
  }, {
    sig : """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

owEBSAG3/pANAwACAZgKPw0B/gTfAcsYYgBTS9qXdGhpcyBpcyB3aXRoIFNIQTEK
iQEcBAABAgAGBQJTS9qXAAoJEJgKPw0B/gTf9FoH/1MO7IFFxBnpLdnWcolVhxT/
R7ZvU2hUTllvhquDG3+3lRECJEcPhCmlfr0tw5CDQjCNOHwqbbiXbAVAq+I3S1J2
EEzneoGzjFEdJiUBMHzbOo4UnIE4TUssiWxnCt5BYWKptjnZ5D416GoIxaSq0vZo
IRw7QlFoIXMfQcsL8cROOhuEhmqtGHck0W/tarbO3ezbHxtcZxiWBXj6UesXlwyL
4mxxLOreEsShBolKz+urofr7OM4ADlrqRYcDTsRCuX8JrhS1G4Uh7KOmW56k/ld2
sR6yXPI2RbMiMyKMS9Z7pDq99d/Wn8VWahU1pN72rI6B65Qcxb4XWqeUFsRfsQU=
=SqWv
-----END PGP MESSAGE-----
""",
    which : "SHA1"
  }, {
    sig : """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

owEBSgG1/pANAwAKAZgKPw0B/gTfAcsaYgBTS9rOdGhpcyBpcyB3aXRoIFNIQTUx
MgqJARwEAAEKAAYFAlNL2s4ACgkQmAo/DQH+BN/sWQgAsoDbzGtMZKvCOmE8/Eiw
mq3d/JbihGY77I7SM6HLOkxqlO6cXXTve3rzUuOPZTmJ/oSscUZPethrYgS/R+AJ
Eb2Cndmzv65HT165Fo+JcN9hC5jJjQZRgqiJxii36OxTcna8mgcNytM0GGkATNEA
SKdRp2uZI+plQogmDjYXip76Io4UNApWFxpKk0N6HN4ns90z+P5Pwv90ulWEwBCx
9EUag/YlYX+SqZoavyhEa6fnEmkQvNOFHScQBRnSnqE6Nl5Uanz5wU+XfTL10Rtj
VRN8iOqxkReADkY+tX+Qj33rVNTjrhrmZ/+i8YGMVvkeNKyrUtxhV0UuSCmz8M2w
/A==
=+r2b
-----END PGP MESSAGE-----
""",
    which : "SHA512"
  }
]

#==================================================================

verify = ({sig,which}, T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, km
  T.no_error err
  await do_message { armored : sig , keyfetch : km }, defer err
  T.no_error err
  T.waypoint which
  cb()

#--------------------------------

exports.verify = (T,cb) ->
  for sig in sigs
    await verify sig, T, defer()
  cb()

#==================================================================

