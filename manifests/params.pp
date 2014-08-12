# == Class: ossec::params
#
# The ossec configuration settings.
#
class ossec::params {

  case $::osfamily {
    'RedHat': {
      $server_package_name        = 'ossec-hids-server'
      $server_package_require     = Yumrepo['atomic']
      $server_service_name        = 'ossec-hids'
      $server_service_hasstatus   = true
      $server_service_hasrestart  = true
      $client_package_name        = 'ossec-hids-client'
      $client_package_require     = Yumrepo['atomic']
      $client_service_name        = 'ossec-hids'
      $client_service_hasstatus   = true
      $client_service_hasrestart  = true
    }

    default: {
      fail("Unsupported osfamily: ${::osfamily}, module ${module_name} only support osfamily RedHat")
    }
  }

  $client_id    = fqdn_rand(99999999, 'ossec')
  $client_seed  = $::uniqueid
  $email_from   = "ossec@${::fqdn}"
  $email_to     = "root@${::domain}"

}
