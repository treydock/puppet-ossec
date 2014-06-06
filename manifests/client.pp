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
    Firewall  <<| title == '100 allow OSSEC' |>> {
      ensure  => $firewall_ensure,
      iniface => undef,
    }
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

  File <<| title == 'ossec-agent.conf' |>>

}
