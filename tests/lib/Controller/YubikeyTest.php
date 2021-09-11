<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\yubikey\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\yubikey\Controller;
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
            ['StateId' => 'abc123']
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
    public function testOtp(): void
    {
        $request = Request::create(
            '/otp',
            'GET',
            ['StateId' => 'abc123', 'otp' => 'aabbccddeeffgghhiijjkkllmmnnooppqq']
        );

        $c = new Controller\Yubikey($this->config, $this->session);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    Auth\State::STAGE => 'yubikey:otp:init',
                    'yubikey:otp' => [
                        'apiKey' => 'abc123',
                        'apiClient' => 'phpunit',
                        'apiHosts' => ['example.org'],
                        'keyIDs' => ['aa'],
                    ],
                ];
            }
        });
        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertInstanceOf(Template::class, $response);
    }
}
