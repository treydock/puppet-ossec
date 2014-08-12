require 'spec_helper'
require 'puppet/util'
require 'digest/md5'

describe 'ossec::clientkey' do
  let(:node) { 'foo.example.com' }
  let(:facts) {{ :concat_basedir => '/dne', :osfamily => 'RedHat', :fqdn => 'foo.example.com' }}
  let(:title) { 'ossec_key_foo.example.com_client' }

  let :params do
    {
      :client_id    => "80864820",
      :client_name  => "foo.example.com",
      :client_ip    => "192.168.1.3",
      :client_seed  => "foobar",
    }
  end

  let(:key1) { 'a57106a7bd9d1c2431993d571b5b6753' }
  let(:key2) { '3cc805a3ea6968adaf2c3adf9a0c28f0' }

  it do
    should contain_concat__fragment('ossec-client-key-192.168.1.3').with({
      :ensure   => 'present',
      :target   => '/var/ossec/etc/client.keys',
      :order    => params[:client_id],
      :content  => "#{params[:client_id]} #{params[:client_name]} #{params[:client_ip]} #{key1}#{key2}\n",
    })
  end
end
