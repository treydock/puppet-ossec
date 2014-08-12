require 'spec_helper'

describe 'ossec::server' do
  let(:node) { 'foo.example.com' } 
  let :facts do
    {
      :osfamily       => 'RedHat',
      :ipaddress_eth0 => '192.168.1.1',
      :network_eth0   => '192.168.1.0',
      :netmask_eth0   => '255.255.255.0',
      :concat_basedir => '/dne',
    }
  end

  it { should create_class('ossec::server') }
  it { should contain_class('ossec::params') }
  it { should contain_class('ossec') }

  it do
    should contain_firewall('100 allow OSSEC clients').with({
      :ensure   => 'present',
      :action   => 'accept',
      :proto    => 'udp',
      :dport    => '1514',
      :iniface  => 'eth0',
      :source   => '192.168.1.0/255.255.255.0',
    })
  end

  it do
    should contain_package('ossec-hids-server').with({
      :ensure  => 'present',
      :name    => 'ossec-hids-server',
      :require => 'Yumrepo[atomic]',
    })
  end

  it do
    should contain_service('ossec-hids').with({
      :ensure      => 'running',
      :enable      => 'true',
      :name        => 'ossec-hids',
      :hasstatus   => 'true',
      :hasrestart  => 'true',
    })
  end

  it do
    should contain_file('/var/ossec/etc/ossec-server.conf').with({
      :ensure   => 'file',
      :owner    => 'root',
      :group    => 'root',
      :mode     => '0644',
      :replace  => 'false',
      :require  => 'Package[ossec-hids-server]',
      :notify   => 'Service[ossec-hids]',
    })
  end

  it do
    content = catalogue.resource('file', '/var/ossec/etc/ossec-server.conf').send(:parameters)[:content]
    content_stripped = content.split("\n").reject { |c| c =~ /(^<!--|^\s+<!--|^$)/ }
    
    expected_lines = [
      '    <email_notification>yes</email_notification>',
      '    <email_to>root@example.com</email_to>',
      '    <smtp_server>localhost</smtp_server>',
      '    <email_from>ossec@foo.example.com</email_from>',
    ]

    (content_stripped & expected_lines).should == expected_lines
  end

  it do
    skip("no way to test exported resources")
    should contain_concat__fragment('ossec-agent.conf-client').with({
      :target   => '/var/ossec/etc/ossec-agent.conf',
      :order    => '01',
      :tag      => 'ossec::client',
    })
  end

  it do
    should contain_concat('/var/ossec/etc/client.keys').with({
      :owner    => 'root',
      :group    => 'ossec',
      :mode     => '0440',
      :require  => 'Package[ossec-hids-server]',
      :notify   => 'Service[ossec-hids]',
    })
  end

  # Test validate_bool parameters
  [
    'email_notification',
    'manage_firewall',
    'server_config_replace',
  ].each do |param|
    context "with #{param} => 'foo'" do
      let(:params) {{ param => 'foo' }}
      it { expect { should create_class('ossec::server') }.to raise_error(Puppet::Error, /is not a boolean/) }
    end
  end
end
