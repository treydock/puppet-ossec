require 'spec_helper'

describe 'ossec::client' do
  let(:node) { 'bar.example.com' } 
  let :facts do
    {
      :osfamily       => 'RedHat',
    }
  end

  it { should create_class('ossec::client') }
  it { should contain_class('ossec::params') }
  it { should contain_class('ossec') }

  it do
    pending "no way to test collected resources" do
      should contain_firewall('100 allow OSSEC server').with({
        :ensure   => 'present',
        :action   => 'accept',
        :proto    => 'udp',
        :dport    => '1514',
        :iniface  => nil,
        :source   => '192.168.1.1',
      })
    end        
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
    pending "no way to test collected resources" do
      should contain_file('/var/ossec/etc/ossec-agent.conf').with({
        :ensure   => 'file',
        :owner    => 'root',
        :group    => 'root',
        :mode     => '0644',
        :require  => 'Package[ossec-hids-client]',
        :notify   => 'Service[ossec-hids]',
      })
    end
  end

  it do
    pending "no way to test collected resources" do
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
