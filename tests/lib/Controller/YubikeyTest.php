<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\yubikey\Controller;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Module\yubikey\Controller;
use SimpleSAML\Module\yubikey\Auth\Process\OTP;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "yubikey" module.
 *
 * @covers \SimpleSAML\Module\yubikey\Controller\Yubikey
 */
class YubikeyTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Session */
    protected Session $session;


    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => ['yubikey' => true],
            ],
            '[ARRAY]',
            'simplesaml'
        );

        $this->session = Session::getSessionFromRequest();

        Configuration::setPreLoadedConfig($this->config, 'config.php');
    }


    /**
     * Test that accessing the otp-endpoint without state results in an error-response
     *
     * @return void
     */
    public function testOtpNoState(): void
    {
        $request = Request::create(
            '/otp',
            'GET'
        );

        $c = new Controller\Yubikey($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage("BADREQUEST('%REASON%' => 'Missing AuthState parameter.')");

        $c->main($request);
    }


    /**
     * Test that accessing the otp-endpoint without otp results in a Template
     *
     * @return void
     */
    public function testOtpNoOtp(): void
    {
        $request = Request::create(
            '/otp',
            'GET',
            ['AuthState' => 'abc123']
        );

        $c = new Controller\Yubikey($this->config, $this->session);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [];
            }
        });
        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertInstanceOf(Template::class, $response);
    }


    /**
     * Test that accessing the otp-endpoint with invalid otp returns Template
     *
     * @return void
     */
    public function testOtpFailed(): void
    {
        $request = Request::create(
            '/otp?AuthState=someState',
            'POST',
            ['otp' => 'aabbccddeeffgghhiijjkkllmmnnooppqq']
        );

        $c = new Controller\Yubikey($this->config, $this->session);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [];
            }
        });
        $c->setOtp(new class (['api_client_id' => 'phpunit', 'api_key' => 'abc123'], []) extends OTP {
            public static function authenticate(array &$state, string $otp): bool
            {
                return false;
            }
        });
        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertInstanceOf(Template::class, $response);
    }


    /**
     * Test that accessing the otp-endpoint with valid otp returns RunnableResponse
     *
     * @return void
     */
    public function testOtpSucceeded(): void
    {
        $request = Request::create(
            '/otp?AuthState=someState',
            'POST',
            ['otp' => 'aabbccddeeffgghhiijjkkllmmnnooppqq']
        );

        $c = new Controller\Yubikey($this->config, $this->session);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [];
            }
        });
        $c->setOtp(new class (['api_client_id' => 'phpunit', 'api_key' => 'abc123'], []) extends OTP {
            public static function authenticate(array &$state, string $otp): bool
            {
                return true;
            }
        });
        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertInstanceOf(RunnableResponse::class, $response);
    }


    /**
     * Test that accessing the otp-endpoint when an unexpected exception occurs returns a Template
     *
     * @return void
     */
    public function testOtpUnexpectedException(): void
    {
        $request = Request::create(
            '/otp?AuthState=someState',
            'POST',
            ['otp' => 'aabbccddeeffgghhiijjkkllmmnnooppqq']
        );

        $c = new Controller\Yubikey($this->config, $this->session);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [];
            }
        });
        $c->setOtp(new class (['api_client_id' => 'phpunit', 'api_key' => 'abc123'], []) extends OTP {
            public static function authenticate(array &$state, string $otp): bool
            {
                throw new InvalidArgumentException("There was an unexpected error while trying to verify your YubiKey.");
            }
        });
        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertInstanceOf(Template::class, $response);
    }
}
