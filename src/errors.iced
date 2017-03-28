
{make_errors} = require 'iced-error'

exports.errors = make_errors {
  WRONG_SIGNING_KEY : "wrong signing key specified"
  REVOKED_KEY : "key is revoked"
}
