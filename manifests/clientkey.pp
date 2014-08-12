#
define ossec::clientkey (
  $client_id,
  $client_name,
  $client_ip,
  $client_seed,
) {

  $key1 = md5("${client_id} ${client_seed}")
  $key2 = md5("${client_name} ${client_ip} ${client_seed}")

  concat::fragment { "ossec-client-key-${client_ip}":
    ensure  => 'present',
    target  => '/var/ossec/etc/client.keys',
    order   => $client_id,
    content => "${client_id} ${client_name} ${client_ip} ${key1}${key2}\n",
  }

}
