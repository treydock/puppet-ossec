# == Class: ossec::client
#
class ossec::client (
  $firewall_ensure    = 'present',
  $manage_firewall    = true,
  $package_name       = $ossec::params::client_package_name,
  $service_ensure     = 'running',
  $service_enable     = true,
  $service_name       = $ossec::params::client_service_name,
  $service_hasstatus  = $ossec::params::client_service_hasstatus,
  $service_hasrestart = $ossec::params::client_service_hasrestart,
  $package_require    = $ossec::params::client_package_require,
) inherits ossec::params {

  validate_bool($manage_firewall)

  include ossec

  if $manage_firewall {
    Firewall  <<| title == '100 allow OSSEC server' |>> {
      ensure  => $firewall_ensure,
    }
  }

  ossec::clientkey { "ossec_key_${::fqdn}_client":
    client_id   => $::uniqueid,
    client_name => $::fqdn,
    client_ip   => $::ipaddress,
  }

  @@ossec::clientkey { "ossec_key_${::fqdn}_server":
    client_id   => $::uniqueid,
    client_name => $::fqdn,
    client_ip   => $::ipaddress,
  }

  package { 'ossec-hids-client':
    ensure  => 'present',
    name    => $package_name,
    require => $package_require,
  }

  service { 'ossec-hids':
    ensure      => $service_ensure,
    enable      => $service_enable,
    name        => $service_name,
    hasstatus   => $service_hasstatus,
    hasrestart  => $service_hasrestart,
  }

  concat { '/var/ossec/etc/client.keys':
    owner   => 'root',
    group   => 'ossec',
    mode    => '0440',
    require => Package['ossec-hids-client'],
    notify  => Service['ossec-hids'],
  }

  File <<| tag == 'ossec::client' |>>

}
