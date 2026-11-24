<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\validator\Validator;
use wise\jwt\validator\ExpirationRule;
use wise\jwt\validator\NotBeforeRule;
use wise\jwt\validator\IssuerRule;
use wise\jwt\validator\AudienceRule;
use wise\jwt\exception\JwtException;

class ValidatorTest extends TestCase
{
    public function testExpirationRule(): void
    {
        $validator = new Validator(0);
        $validator->addRule(new ExpirationRule(0));

        $validator->validate(['exp' => time() + 3600]);
        $this->assertTrue(true);

        $this->expectException(JwtException::class);
        $validator->validate(['exp' => time() - 1]);
    }

    public function testExpirationRuleWithLeeway(): void
    {
        $validator = new Validator(60);
        $validator->addRule(new ExpirationRule(60));

        $validator->validate(['exp' => time() - 30]);
        $this->assertTrue(true);
    }

    public function testNotBeforeRule(): void
    {
        $validator = new Validator(0);
        $validator->addRule(new NotBeforeRule(0));

        $validator->validate(['nbf' => time() - 60]);
        $this->assertTrue(true);

        $this->expectException(JwtException::class);
        $validator->validate(['nbf' => time() + 3600]);
    }

    public function testIssuerRule(): void
    {
        $validator = new Validator();
        $validator->addRule(new IssuerRule('wiseadmin'));

        $validator->validate(['iss' => 'wiseadmin']);
        $this->assertTrue(true);

        $this->expectException(JwtException::class);
        $validator->validate(['iss' => 'attacker']);
    }

    public function testAudienceRule(): void
    {
        $validator = new Validator();
        $validator->addRule(new AudienceRule('app'));

        $validator->validate(['aud' => 'app']);
        $this->assertTrue(true);

        $validator->validate(['aud' => ['web', 'app']]);
        $this->assertTrue(true);

        $this->expectException(JwtException::class);
        $validator->validate(['aud' => 'other']);
    }

    public function testRuleRemoval(): void
    {
        $validator = new Validator();
        $validator->addRule(new ExpirationRule(0));
        $validator->removeRule(ExpirationRule::class);

        $validator->validate(['exp' => time() - 99999]);
        $this->assertTrue(true);
    }

    public function testEmptyValidatorPasses(): void
    {
        $validator = new Validator();
        $validator->validate(['anything' => 'goes']);
        $this->assertTrue(true);
    }
}
