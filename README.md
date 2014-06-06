# puppet-ossec

[![Build Status](https://travis-ci.org/treydock/puppet-ossec.png)](https://travis-ci.org/treydock/puppet-ossec)

## Overview

Manages OSSEC server and OSSEC clients.

## Support

Currently only supports Enterprise Linux based systems.

Adding support for other Linux distributions should only require
new variables being added to ossec::params case statement.

## Usage

### ossec::server

To install an OSSEC server

    class { 'ossec::server': }

### ossec::client

To install an OSSEC client

    class { 'ossec::client': }

## Reference

### Classes

#### Public classes

* `ossec::server` - Installs and configures an OSSEC server
* `ossec::client` - Installs and configures an OSSEC client

#### Private classes

* `ossec` - Currently only ensures that the atomic class is included
* `ossec::params` - Defines default values based on osfamily

### Parameters

#### ossec::server


#### ossec::client


## Development

### Testing

Testing requires the following dependencies:

* rake
* bundler

Install gem dependencies

    bundle install

Run unit tests

    bundle exec rake test

If you have Vagrant >= 1.2.0 installed you can run system tests

    bundle exec rake acceptance

## TODO

* 
