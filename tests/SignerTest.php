<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use wise\jwt\signer\HS256Signer;
use wise\jwt\signer\HS384Signer;
use wise\jwt\signer\HS512Signer;

class SignerTest extends TestCase
{
    private string $header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
    private string $payload = 'eyJzdWIiOiIxMjM0NTY3ODkwIn0';

    #[DataProvider('hmacProvider')]
    public function testHmacSignVerify(string $signerClass, string $algoName): void
    {
        $secret = 'my-secret-key-for-testing';
        $signer = new $signerClass($secret);

        $signature = $signer->sign($this->header, $this->payload);
        $this->assertNotEmpty($signature);
        $this->assertEquals($algoName, $signer->algorithm());

        $this->assertTrue($signer->verify($this->header, $this->payload, $signature));
        $this->assertFalse($signer->verify($this->header, 'tampered', $signature));
    }

    public static function hmacProvider(): array
    {
        return [
            'HS256' => [HS256Signer::class, 'HS256'],
            'HS384' => [HS384Signer::class, 'HS384'],
            'HS512' => [HS512Signer::class, 'HS512'],
        ];
    }

    public function testHmacTamperedSignatureFails(): void
    {
        $signer = new HS256Signer('secret');
        $sig = $signer->sign($this->header, $this->payload);

        // 翻转一个字节
        $sig[0] = chr(ord($sig[0]) ^ 0xFF);
        $this->assertFalse($signer->verify($this->header, $this->payload, $sig));
    }

    public function testHmacDifferentSecretFails(): void
    {
        $s1 = new HS256Signer('secret-a');
        $s2 = new HS256Signer('secret-b');

        $sig = $s1->sign($this->header, $this->payload);
        $this->assertFalse($s2->verify($this->header, $this->payload, $sig));
    }
}
