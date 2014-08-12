require 'spec_helper'

describe 'ossec::client' do
  let(:node) { 'bar.example.com' } 
  let :facts do
    {
      :concat_basedir => '/dne',
      :osfamily       => 'RedHat',
      :concat_basedir => '/dne',
      :uniqueid       => 'foobar',
      :fqdn           => 'foo.example.com',
      :ipaddress      => '192.168.1.2',
    }
  end

  it { should create_class('ossec::client') }
  it { should contain_class('ossec::params') }
  it { should contain_class('ossec') }

  it do
    skip("no way to test collected resources")
    should contain_firewall('100 allow OSSEC server').with({
      :ensure   => 'present',
      :action   => 'accept',
      :proto    => 'udp',
      :dport    => '1514',
      :iniface  => nil,
      :source   => '192.168.1.1',
    })
  end

  it do
    should contain_concat('/var/ossec/etc/client.keys').with({
      :owner    => 'root',
      :group    => 'ossec',
      :mode     => '0440',
      :require  => 'Package[ossec-hids-client]',
      :notify   => 'Service[ossec-hids]',
    })
  end

  it do
    should contain_ossec__clientkey('ossec_key_foo.example.com_client').with({
      :client_id    => 'foobar',
      :client_name  => 'foo.example.com',
      :client_ip    => '192.168.1.2',
    })
  end

  it do
    skip("No way to test exported resources")
    should contain_ossec__clientkey('ossec_key_foo.example.com_server').with({
      :client_id    => 'foobar',
      :client_name  => 'foo.example.com',
      :client_ip    => '192.168.1.2',
    })
  end

  it do
    should contain_package('ossec-hids-client').with({
      :ensure  => 'present',
      :name    => 'ossec-hids-client',
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
    should contain_concat('/var/ossec/etc/ossec-agent.conf').with({
      :ensure   => 'present',
      :owner    => 'root',
      :group    => 'root',
      :mode     => '0644',
      :require  => 'Package[ossec-hids-client]',
      :notify   => 'Service[ossec-hids]',
    })
  end

  it do
    should contain_concat__fragment('ossec-agent.conf-open').with({
      :target   => '/var/ossec/etc/ossec-agent.conf',
      :content  => "<ossec_config>\n",
      :order    => '00',
    })
  end

  it do
    skip("no way to test collected resources")
    should contain_concat__fragment('ossec-agent.conf-client').with({
      :target   => '/var/ossec/etc/ossec-agent.conf',
      :order    => '01',
      :tag      => 'ossec::client',
    })
  end

  it do
    should contain_concat__fragment('ossec-agent.conf-repeated_offenders').with({
      :target   => '/var/ossec/etc/ossec-agent.conf',
      :content  => '',
      :order    => '10',
    })
  end

  it do
    should contain_concat__fragment('ossec-agent.conf-close').with({
      :target   => '/var/ossec/etc/ossec-agent.conf',
      :content  => "</ossec_config>\n",
      :order    => '99',
    })
  end

  it do
    skip("no way to test collected resources")
    content = catalogue.resource('file', '/var/ossec/etc/ossec-agent.conf').send(:parameters)[:content]
    content_stripped = content.split("\n").reject { |c| c =~ /(^<!--|^\s+<!--|^$)/ }
  
    expected_lines = [
      '<ossec_config>',
      '  <client>',
      '    <server-ip>192.168.200.1</server-ip>',
      '    <server-hostname>foo.example.com</server-hostname>',
      '    <port>1514</port>',
      '  </client>',
      '</ossec_config>',
    ]

    (content_stripped & expected_lines).should == expected_lines
  end

  context 'when repeated_offenders => [30,120,360,420,840]' do
    let(:params) {{ :repeated_offenders => [30,120,360,420,840] }}

    it do
      should contain_concat__fragment('ossec-agent.conf-repeated_offenders').with({
        :target   => '/var/ossec/etc/ossec-agent.conf',
        :content  => "  <active-response>
    <repeated_offenders>30,120,360,420,840</repeated_offenders>
  </active-response>\n",
        :order    => '10',
      })
    end
  end

  # Test validate_array parameters
  [
    'repeated_offenders',
  ].each do |param|
    context "with #{param} => 'foo'" do
      let(:params) {{ param => 'foo' }}
      it { expect { should create_class('ossec::client') }.to raise_error(Puppet::Error, /is not an Array/) }
    end
  end

  # Test validate_bool parameters
  [
    'manage_firewall',
  ].each do |param|
    context "with #{param} => 'foo'" do
      let(:params) {{ param => 'foo' }}
      it { expect { should create_class('ossec::client') }.to raise_error(Puppet::Error, /is not a boolean/) }
    end
  end
end
