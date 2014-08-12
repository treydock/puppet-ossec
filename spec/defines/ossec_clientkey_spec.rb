require 'spec_helper'
require 'puppet/util'
require 'digest/md5'

describe 'ossec::clientkey' do
  let(:node) { 'foo.example.com' }
  let(:facts) {{ :concat_basedir => '/dne', :osfamily => 'RedHat', :fqdn => 'foo.example.com' }}
  let(:title) { 'ossec_key_foo.example.com_client' }

  let :params do
    {
      :client_id    => "a8c0f9cb",
      :client_name  => "foo.example.com",
      :client_ip    => "192.168.1.3",
    }
  end

  let(:key1) { 'cffe40a7d9441096a257fad40b21179c' }
  let(:key2) { '53a9e373dba1a7e2f914949599c84ccc' }

  it do
    should contain_concat__fragment('ossec-client-key-192.168.1.3').with({
      :ensure   => 'present',
      :target   => '/var/ossec/etc/client.keys',
      :order    => params[:client_id],
      :content  => "#{params[:client_id]} #{params[:client_name]} #{params[:client_ip]} #{key1}#{key2}\n",
    })
  end
end
