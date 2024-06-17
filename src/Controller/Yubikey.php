<?php

declare(strict_types=1);

namespace SimpleSAML\Module\yubikey\Controller;

use InvalidArgumentException;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
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
    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected $authState = Auth\State::class;

    /**
     * @var \SimpleSAML\Module\yubikey\Auth\Process\OTP|string
     * @psalm-var \SimpleSAML\Module\yubikey\Auth\Process\OTP|class-string
     */
    protected $otp = OTP::class;


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
        protected Configuration $config,
        protected Session $session,
    ) {
    }


    /**
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param \SimpleSAML\Auth\State $authState
     */
    public function setAuthState(Auth\State $authState): void
    {
        $this->authState = $authState;
    }


    /**
     * Inject the \SimpleSAML\Module\yubikey\Auth\Process\OTP dependency.
     *
     * @param \SimpleSAML\Module\yubikey\Auth\Process\OTP $otp
     */
    public function setOtp(OTP $otp): void
    {
        $this->otp = $otp;
    }


    /**
     * This page asks the user to authenticate using a Yubikey.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The current request.
     * @return \SimpleSAML\XHTML\Template|\SimpleSAML\HTTP\RunnableResponse
     */
    public function main(Request $request)
    {
        $stateId = $request->query->get('AuthState');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        $state = $this->authState::loadState($stateId, 'yubikey:otp:init');

        $error = false;

        $otp = $request->request->get('otp');
        if ($otp !== null) {
            // we were given an OTP
            try {
                if ($this->otp::authenticate($state, $otp)) {
                    $this->authState::saveState($state, 'yubikey:otp:init');
                    return new RunnableResponse([Auth\ProcessingChain::class, 'resumeProcessing'], [$state]);
                } else {
                    $error = 'The YubiKey used is invalid. Make sure to use the YubiKey associated with your account.';
                }
            } catch (InvalidArgumentException $e) {
                $error = $e->getMessage();
            }
        }

        $t = new Template($this->config, 'yubikey:otp.twig');
        $t->data['AuthState'] = $stateId;
        $t->data['error'] = $error || false;
        $t->data['autofocus'] = 'otp';

        return $t;
    }
}
