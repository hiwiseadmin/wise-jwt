<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\JwtGuardManager;
use wise\jwt\Jwt;
use wise\jwt\TokenPair;
use wise\jwt\exception\JwtException;

/**
 * 多 Guard 管理器测试
 */
class JwtGuardManagerTest extends TestCase
{
    protected array $config;
    protected JwtGuardManager $manager;

    protected function setUp(): void
    {
        $this->config = [
            'default'   => 'app',
            'algorithm' => 'HS256',
            'secret'    => 'shared-secret-32bytes-long!!111',
            'issuer'    => 'wiseadmin',
            'ttl'       => 7200,
            'refresh_ttl' => 1800,
            'refresh_token_ttl' => 2592000,
            'leeway'    => 0,
            'blacklist' => ['enable' => false],
            'validation' => [
                'check_expiration' => true,
                'check_not_before' => true,
                'check_issuer'     => true,
                'check_audience'   => false,
            ],
            'guards' => [
                'app' => [
                    'algorithm' => 'HS256',
                    'secret'    => 'app-secret-32bytes-long!!11111',
                    'issuer'    => 'wiseadmin-app',
                    'ttl'       => 7200,
                    'refresh_token_ttl' => 2592000,
                    'blacklist' => ['enable' => false],
                ],
                'admin' => [
                    'algorithm' => 'HS256',
                    'secret'    => 'admin-secret-32bytes-long!!!11',
                    'issuer'    => 'wiseadmin-admin',
                    'ttl'       => 3600,
                    'refresh_token_ttl' => 1209600,
                    'blacklist' => ['enable' => false],
                ],
            ],
        ];

        // 使用纯配置数组构造（不依赖 think\App）
        $this->manager = new JwtGuardManager($this->config);
    }

    /** @test 获取默认 guard */
    public function testDefaultGuard(): void
    {
        $jwt = $this->manager->guard();
        $this->assertInstanceOf(Jwt::class, $jwt);
        $this->assertEquals('wiseadmin-app', $jwt->getIssuer());
    }

    /** @test 获取指定 guard */
    public function testGetGuardByName(): void
    {
        $adminJwt = $this->manager->guard('admin');
        $this->assertInstanceOf(Jwt::class, $adminJwt);
        $this->assertEquals('wiseadmin-admin', $adminJwt->getIssuer());
    }

    /** @test 不存在 guard 抛出异常 */
    public function testUnknownGuardThrowsException(): void
    {
        $this->expectException(JwtException::class);
        $this->manager->guard('nonexistent');
    }

    /** @test 不同 guard 使用不同配置 */
    public function testDifferentGuardsHaveDifferentConfigs(): void
    {
        $appJwt = $this->manager->guard('app');
        $adminJwt = $this->manager->guard('admin');

        $this->assertEquals('wiseadmin-app', $appJwt->getIssuer());
        $this->assertEquals('wiseadmin-admin', $adminJwt->getIssuer());
        $this->assertEquals(7200, $appJwt->getTtl());
        $this->assertEquals(3600, $adminJwt->getTtl());
    }

    /** @test 不同 guard 签发不同 token */
    public function testDifferentGuardsIssueDifferentTokens(): void
    {
        $appJwt = $this->manager->guard('app');
        $adminJwt = $this->manager->guard('admin');

        $appToken = $appJwt->issue('user-1');
        $adminToken = $adminJwt->issue('user-1');

        // 不同密钥签发的 token 应该不同
        $this->assertNotEquals($appToken, $adminToken);

        // app guard 的 token 可以被 app guard 解析
        $appPayload = $appJwt->parse($appToken);
        $this->assertEquals('user-1', $appPayload['sub']);
        $this->assertEquals('wiseadmin-app', $appPayload['iss']);

        // admin guard 的 token 可以被 admin guard 解析
        $adminPayload = $adminJwt->parse($adminToken);
        $this->assertEquals('user-1', $adminPayload['sub']);
        $this->assertEquals('wiseadmin-admin', $adminPayload['iss']);
    }

    /** @test 跨 guard 解析应失败（不同密钥） */
    public function testCrossGuardParseFails(): void
    {
        $appJwt = $this->manager->guard('app');
        $adminJwt = $this->manager->guard('admin');

        $adminToken = $adminJwt->issue('user-1');

        // app guard 尝试解析 admin guard 签发的 token → 签名不匹配
        $result = $appJwt->tryParse($adminToken);
        $this->assertNull($result, '跨 guard 解析应返回 null');
    }

    /** @test 相同 guard 的实例被缓存 */
    public function testGuardInstancesAreCached(): void
    {
        $jwt1 = $this->manager->guard('admin');
        $jwt2 = $this->manager->guard('admin');
        $this->assertSame($jwt1, $jwt2);
    }

    /** @test getDefaultGuard 返回配置的默认 guard */
    public function testGetDefaultGuard(): void
    {
        $this->assertEquals('app', $this->manager->getDefaultGuard());
    }

    /** @test defaultJwt 返回默认 guard 的实例 */
    public function testDefaultJwt(): void
    {
        $jwt = $this->manager->defaultJwt();
        $this->assertInstanceOf(Jwt::class, $jwt);
    }

    /** @test flush 清除指定 guard 缓存 */
    public function testFlushRemovesCache(): void
    {
        $jwt1 = $this->manager->guard('admin');
        $this->manager->flush('admin');
        $jwt2 = $this->manager->guard('admin');
        $this->assertNotSame($jwt1, $jwt2);
    }

    /** @test flush 无参数清除所有缓存 */
    public function testFlushAllRemovesAllCache(): void
    {
        $appJwt1 = $this->manager->guard('app');
        $adminJwt1 = $this->manager->guard('admin');

        $this->manager->flush();

        $appJwt2 = $this->manager->guard('app');
        $adminJwt2 = $this->manager->guard('admin');

        $this->assertNotSame($appJwt1, $appJwt2);
        $this->assertNotSame($adminJwt1, $adminJwt2);
    }

    /** @test 多 Guard 支持双令牌模式 */
    public function testIssuePairWithDifferentGuards(): void
    {
        $appJwt = $this->manager->guard('app');
        $adminJwt = $this->manager->guard('admin');

        $appPair = $appJwt->issuePair('user-1', ['role' => 'user']);
        $adminPair = $adminJwt->issuePair('admin-1', ['role' => 'superadmin']);

        $this->assertInstanceOf(TokenPair::class, $appPair);
        $this->assertInstanceOf(TokenPair::class, $adminPair);

        // 各自可解析自己的 token
        $appPayload = $appJwt->parse($appPair->accessToken);
        $adminPayload = $adminJwt->parse($adminPair->accessToken);

        $this->assertEquals('user', $appPayload['role']);
        $this->assertEquals('superadmin', $adminPayload['role']);
    }

    /** @test 不同 guard 有不同的 Refresh Token TTL */
    public function testGuardsHaveDifferentRefreshTtls(): void
    {
        $appPair = $this->manager->guard('app')->issuePair('user-1');
        $adminPair = $this->manager->guard('admin')->issuePair('admin-1');

        $this->assertEquals(2592000, $appPair->refreshExpiresIn);
        $this->assertEquals(1209600, $adminPair->refreshExpiresIn);
    }
}
