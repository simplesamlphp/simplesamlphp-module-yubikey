![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-yubikey/workflows/CI/badge.svg?branch=master)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-yubikey/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-yubikey)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-yubikey/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-yubikey/?branch=master)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-yubikey/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-yubikey)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-yubikey/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-yubikey)

YubiKey
=======

This is a SimpleSAMLphp module to leverage YubiKey devices to authenticate users in different ways.
For the moment, it provides an authentication processing filter that allows you to require a user
to use a YubiKey to complete authentication, effectively implementing two-factor authentication.
This filter can be combined with any other authentication source, provided that the identifier (or
identifiers) of the key registered for that user is available as an attribute.

Installation
------------

Once you have installed SimpleSAMLphp, installing this module is very simple. Just execute the following
command in the root of your SimpleSAMLphp installation:

```shell
composer.phar require simplesamlphp/simplesamlphp-module-yubikey
```

Then, you need to do is to enable the Yubikey module: in
 `config.php`, search for the `module.enable` key and set `yubikey` to true:

 ```php
     'module.enable' => [
          'yubikey' => true,
          …
     ],
 ```


OTP authentication processing filter
------------------------------------

This filter allows you to ask for YubiKey authentication before proceeding further. As any other processing
filter, it can be configured [either in the general configuration, in the authsources, in the hosted
IdP metadata or in the remote SP metadata](https://simplesamlphp.org/docs/stable/simplesamlphp-authproc#section_1).

You can configure the filter by adding an authproc filter with the class `yubikey:OTP`. At the very
least, you will need an API client identifier and an API key. By default, the filter will let you
use [YubiCloud](https://www.yubico.com/products/services-software/yubicloud/), which will require
you to [register](https://upgrade.yubico.com/getapikey/) to obtain a client identifier and an API key.

If you would like to run the YubiKey validation server yourself (i.e. the server running the API), [you
can also do it](https://developers.yubico.com/Software_Projects/Yubico_OTP/YubiCloud_Validation_Servers/). In
that case, you will need to configure the hostname of your validation server instead of the default addresses.

Here are all the options available:

**API configuration options**

-  `api_client_id`: The client identifier to present to the API. This option is **mandatory**.
-  `api_key`: The key that grants you access to the YubiKey API. This option is **mandatory**.
-  `api_hosts`: An array containing the hosts where the API can be contacted to authenticate a given YubiKey.
    Please note that **all hosts will be queried**, and **all the responses must be successful** in order to
    consider the authentication of a device to be successful. Therefore, if you want to use your own API with
    high availability, you should only specify one hostname here and configure a high availability setup for
    that hostname.
    This is optional and defaults to Yubico's public API servers, those being:
     - `api.yubico.com`
 
**Operational configuration options**

-  `abort_if_missing`: A boolean value telling whether the whole login process should be aborted if
the user has no YubiKey devices registered (set to `true`) or continue, skipping YubiKey authentication
(set to `false`). Optional. Defaults to `false`.
-  `key_id_attribute`: This is the name of an attribute that holds one or more YubiKey device identifiers
that are known and accepted for the user. Optional. Defaults to `yubikey`.

**Assurance configuration options**

-  `assurance_attribute`: This is the name of an attribute that we will use to indicate that a successful
authentication with the YubiKey device was performed (only when authentication was successful, of course). 
Optional. Defaults to `eduPersonAssurance`.
-  `assurance_value`: This is the value that we will add to the attribute specified by `assurance_attribute`.
Optional. Defaults to `OTP`.


