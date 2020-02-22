<?php

/**
 * This page asks the user to authenticate using a Yubikey.
 *
 * @author Jaime Pérez Crespo, UNINETT AS <jaime.perez@uninett.no>.
 * @package SimpleSAMLphp\Module\yubikey
 */

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new \SimpleSAML\Error\BadRequest('Missing AuthState parameter.');
}
$authStateId = $_REQUEST['StateId'];
/** @var array $state */
$state = \SimpleSAML\Auth\State::loadState($authStateId, 'yubikey:otp:init');

$error = false;
if (array_key_exists('otp', $_POST)) {
    // we were given an OTP
    try {
        if (\SimpleSAML\Module\yubikey\Auth\Process\OTP::authenticate($state, $_POST['otp'])) {
            \SimpleSAML\Auth\State::saveState($state, 'yubikey:otp:init');
            \SimpleSAML\Auth\ProcessingChain::resumeProcessing($state);
        } else {
            $error = '{yubikey:errors:invalid_yubikey}';
        }
    } catch (\InvalidArgumentException $e) {
        $error = $e->getMessage();
    }
}

$cfg = \SimpleSAML\Configuration::getInstance();
$tpl = new \SimpleSAML\XHTML\Template($cfg, 'yubikey:otp.twig');
$trans = $tpl->getTranslator();
$tpl->data['params'] = ['StateId' => $authStateId];
$tpl->data['error'] = $error || false;
$tpl->data['autofocus'] = 'otp';
$tpl->send();
