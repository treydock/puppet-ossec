# == Class: ossec
#
class ossec (

) inherits ossec::params {

  case $::osfamily {
    'RedHat': {
      include atomic
    }

    default: {
      # Do nothing
    }
  }

}
