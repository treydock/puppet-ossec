#
define ossec::clientkey (
  $client_id,
  $client_name,
  $client_ip,
  $client_seed = 'UNSET',
) {

  include ossec::params

  if $client_seed == 'UNSET' {
    $client_seed_real = $ossec::params::client_seed
  } else {
    $client_seed_real = $client_seed
  }

  $key1 = md5("${client_id} ${client_seed_real}")
  $key2 = md5("${client_name} ${client_ip} ${client_seed_real}")

  concat::fragment { "ossec-client-key-${client_ip}":
    ensure  => 'present',
    target  => '/var/ossec/etc/client.keys',
    order   => $client_id,
    content => "${client_id} ${client_name} ${client_ip} ${key1}${key2}\n",
  }

}
