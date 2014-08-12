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
    }
  end

  let(:key1) { '87747bc021753281e41508e783771591' }
  let(:key2) { '2587d242d0a618db0020a6e6c73f8c64' }

  it do
    should contain_concat__fragment('ossec-client-key-192.168.1.3').with({
      :ensure   => 'present',
      :target   => '/var/ossec/etc/client.keys',
      :order    => params[:client_id],
      :content  => "#{params[:client_id]} #{params[:client_name]} #{params[:client_ip]} #{key1}#{key2}\n",
    })
  end
end
