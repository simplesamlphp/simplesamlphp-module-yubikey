<?php

/**
 * An authentication processing filter that allows you to use your yubikey as an OTP second factor.
 *
 * @package SimpleSAML\Module\yubikey
 */

declare(strict_types=1);

namespace SimpleSAML\Module\yubikey\Auth\Process;

use Exception;
use InvalidArgumentException;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Module;
use SimpleSAML\Logger;
use SimpleSAML\Session;
use SimpleSAML\Utils;

class OTP extends Auth\ProcessingFilter
{
    /**
     * The API client identifier.
     *
     * @var string
     */
    private string $apiClient;

    /**
     * The API key to use.
     *
     * @var string
     */
    private string $apiKey;

    /**
     * An array of hosts to be used for API calls.
     *
     * Defaults to:
     * - api.yubico.com
     * - api2.yubico.com
     * - api3.yubico.com
     * - api4.yubico.com
     * - api5.yubico.com
     *
     * @var array
     */
    private array $apiHosts;

    /**
     * Whether to abort authentication if no yubikey is known for the user or not.
     *
     * @var bool
     */
    private bool $abortIfMissing;

    /**
     * The name of the attribute containing the yubikey ID.
     *
     * Defaults to "yubikey".
     *
     * @var string
     */
    private string $keyIdAttr;

    /**
     * The name of the attribute that expresses successful authentication with the yubikey.
     *
     * Defaults to "eduPersonAssurance".
     *
     * @var string
     */
    private string $assuranceAttr;

    /**
     * The value of the "assurance" attribute that conveys successful authentication with a yubikey.
     *
     * Defaults to "OTP".
     *
     * @var string
     */
    private string $assuranceValue;

    /**
     * Whether to remember a previous authentication or keep asking.
     *
     * @TODO Not yet implemented
     *
     * @var boolean
     */
    private bool $remember;

    /**
     * The auth source associated with this authproc.
     *
     * @var string
     */
    private string $authid;


    /**
     * OTP constructor.
     *
     * @param array $config The configuration of this authproc.
     * @param mixed $reserved
     *
     * @throws \SimpleSAML\Error\CriticalConfigurationError in case the configuration is wrong.
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $cfg = Configuration::loadFromArray($config, 'yubikey:OTP');
        $this->apiClient = $cfg->getString('api_client_id');
        $this->apiKey = $cfg->getString('api_key');
        $this->abortIfMissing = $cfg->getOptionalBoolean('abort_if_missing', false);
        $this->keyIdAttr = $cfg->getOptionalString('key_id_attribute', 'yubikey');
        $this->assuranceAttr = $cfg->getOptionalString('assurance_attribute', 'eduPersonAssurance');
        $this->assuranceValue = $cfg->getOptionalString('assurance_value', 'OTP');
        $this->apiHosts = $cfg->getOptionalArrayize('api_hosts', [
            'api.yubico.com',
        ]);
        $this->remember = $cfg->getOptionalBoolean('just_once', true);
    }


    /**
     * Run the filter.
     *
     * @param array $state
     *
     * @throws \Exception if there is no yubikey ID and we are told to abort in such case.
     */
    public function process(array &$state): void
    {
        $session = Session::getSessionFromRequest();
        $this->authid = $state['Source']['auth'];
        $key_id = $session->getData('yubikey:auth', $this->authid);
        $attrs = &$state['Attributes'];

        // missing attribute, yubikey auth required
        if ($this->abortIfMissing && !array_key_exists($this->keyIdAttr, $attrs)) {
            // TODO: display an error page instead of an exception
            throw new Exception('Missing key ID.');
        }

        // missing attribute, but not required
        if (!array_key_exists($this->keyIdAttr, $attrs)) {
            // nothing we can do here
            return;
        }

        // check for previous auth
        if (!is_null($key_id) && in_array($key_id, $attrs[$this->keyIdAttr], true)) {
            // we were already authenticated using a valid yubikey
            Logger::info('Reusing previous YubiKey authentication with key "' . $key_id . '".');
            return;
        }

        $state['yubikey:otp'] = [
            'apiClient' => $this->apiClient,
            'apiKey' => $this->apiKey,
            'assuranceAttribute' => $this->assuranceAttr,
            'assuranceValue' => $this->assuranceValue,
            'apiHosts' => $this->apiHosts,
            'keyIDs' => $attrs[$this->keyIdAttr],
            'authID' => $this->authid,
            'self' => $this,
        ];

        Logger::debug('Initiating YubiKey authentication.');

        $sid = Auth\State::saveState($state, 'yubikey:otp:init');
        $url = Module::getModuleURL('yubikey/otp');

        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, ['StateId' => $sid]);
    }


    /**
     * Perform OTP authentication given the current state and a one time password obtained from a yubikey.
     *
     * @param array $state The state array in the "yubikey:otp:init" stage.
     * @param string $otp A one time password generated by a yubikey.
     * @return boolean True if authentication succeeded and the key belongs to the user, false otherwise.
     *
     * @throws \InvalidArgumentException if the state array is not in a valid stage or the given OTP has incorrect
     * length.
     */
    public static function authenticate(array &$state, string $otp): bool
    {
        // validate the state array we're given
        if (
            !array_key_exists(Auth\State::STAGE, $state) ||
            $state[Auth\State::STAGE] !== 'yubikey:otp:init'
        ) {
            throw new InvalidArgumentException("There was an unexpected error while trying to verify your YubiKey.");
        }
        $cfg = $state['yubikey:otp'];

        // validate the OTP we are given
        $otplen = strlen($otp);
        if ($otplen < 32 || $otplen > 48) {
            throw new InvalidArgumentException(
                "The one time password generated by your YubiKey is not valid. Please make"
                . " sure to use your YubiKey. You don't have to type anything manually."
            );
        }
        $otp = strtolower($otp);

        // obtain the identity of the yubikey
        $kid = substr($otp, 0, -32);
        Logger::debug('Verifying Yubikey ID "' . $kid . '"');

        // verify the OTP against the API
        $api = new \Yubikey\Validate($cfg['apiKey'], $cfg['apiClient']);
        $api->setHosts($cfg['apiHosts']);
        $resp = $api->check($otp, true);

        // verify the identity corresponds to this user
        if (!in_array($kid, $cfg['keyIDs'], true)) {
            Logger::warning('The YubiKey "' . $kid . '" is not valid for this user.');
            Logger::stats('yubikey:otp: invalid YubiKey.');
            return false;
        }

        // check if the response is successful
        if ($resp->success()) {
            $state['Attributes'][$state['yubikey:otp']['assuranceAttribute']][] =
                $state['yubikey:otp']['assuranceValue'];

            // keep authentication data in the session
            $session = Session::getSessionFromRequest();
            $session->setData('yubikey:auth', $cfg['authID'], $kid);
            $session->registerLogoutHandler(
                $cfg['authID'],
                $cfg['self'],
                'logoutHandler'
            );
            Logger::info('Successful authentication with YubiKey "' . $kid . '".');
            return true;
        }
        Logger::warning('Couldn\'t successfully authenticate YubiKey "' . $kid . '".');
        return false;
    }


    /**
     * A logout handler that makes sure to remove the key from the session, so that the user is asked for the key again
     * in case of a re-authentication with this very same session.
     */
    public function logoutHandler(): void
    {
        $session = Session::getSessionFromRequest();
        $keyid = $session->getData('yubikey:auth', $this->authid);
        Logger::info('Removing valid YubiKey authentication with key "' . $keyid . '".');
        $session->deleteData('yubikey:auth', $this->authid);
    }
}
