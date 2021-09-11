<?php

declare(strict_types=1);

namespace SimpleSAML\Module\yubikey\Controller;

use InvalidArgumentException;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\yubikey\Auth\Process\OTP;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the yubikey module.
 *
 * This class serves the different views available in the module.
 *
 * @package simplesamlphp/simplesamlphp-module-yubikey
 */
class Yubikey
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Session */
    protected Session $session;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and session for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session $session The session to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config,
        Session $session
    ) {
        $this->config = $config;
        $this->session = $session;
    }


    /**
     * This page asks the user to authenticate using a Yubikey.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The current request.
     * @return \SimpleSAML\XHTML\Template
     */
    public function main(Request $request): Template
    {
        $stateId = $request->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        /** @var array $state */
        $state = Auth\State::loadState($stateId, 'yubikey:otp:init');

        $error = false;

        $otp = $request->get('otp');
        if ($otp !== null) {
            // we were given an OTP
            try {
                if (OTP::authenticate($state, $otp)) {
                    Auth\State::saveState($state, 'yubikey:otp:init');
                    Auth\ProcessingChain::resumeProcessing($state);
                } else {
                    $error = 'The YubiKey used is invalid. Make sure to use the YubiKey associated with your account.';
                }
            } catch (InvalidArgumentException $e) {
                $error = $e->getMessage();
            }
        }

        $t = new Template($this->config, 'yubikey:otp.twig');
        $t->data['params'] = ['StateId' => $stateId];
        $t->data['error'] = $error || false;
        $t->data['autofocus'] = 'otp';

        return $t;
    }
}
