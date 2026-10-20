<?php
declare(strict_types=1);

namespace wise\jwt;

/**
 * JWT 流式签发构建器
 *
 * 单令牌模式：
 * $token = $jwt->builder()
 *     ->subject($userId)
 *     ->claim('role', 'admin')
 *     ->ttl(3600)
 *     ->issue();
 *
 * 双令牌模式：
 * $pair = $jwt->builder()
 *     ->subject($userId)
 *     ->claim('role', 'admin')
 *     ->accessTtl(7200)
 *     ->refreshTtl(2592000)
 *     ->issuePair();
 *
 * 签发 Refresh Token：
 * $refreshToken = $jwt->builder()
 *     ->asRefreshToken()
 *     ->subject($userId)
 *     ->ttl(86400 * 30)
 *     ->issue();
 */
class Builder
{
    protected ?string $subject = null;
    protected ?string $issuer = null;
    protected string|array|null $audience = null;
    protected int $ttl;
    protected array $claims = [];
    protected array $headers = [];
    protected ?int $notBefore = null;
    protected ?string $jti = null;
    protected bool $isRefreshToken = false;

    /** @var int|null Access Token 有效期（双令牌模式） */
    protected ?int $accessTtl = null;

    /** @var int|null Refresh Token 有效期（双令牌模式） */
    protected ?int $refreshTtl = null;

    /** @var bool 是否启用 Refresh Token Rotation */
    protected ?bool $rotation = null;

    /** @var bool|null 是否启用 Refresh Token 指纹绑定 */
    protected ?bool $refreshTokenFingerprint = null;

    public function __construct(protected Jwt $jwt)
    {
        $this->ttl = $jwt->getTtl();
    }

    public function subject(string|int $sub): self { $this->subject = (string) $sub; return $this; }
    public function issuer(string $iss): self { $this->issuer = $iss; return $this; }
    public function audience(string|array $aud): self { $this->audience = $aud; return $this; }
    public function claim(string $key, mixed $value): self { $this->claims[$key] = $value; return $this; }
    public function claims(array $claims): self { $this->claims = array_merge($this->claims, $claims); return $this; }
    public function ttl(int $seconds): self { $this->ttl = $seconds; return $this; }
    public function notBefore(int $timestamp): self { $this->notBefore = $timestamp; return $this; }
    public function jti(string $jti): self { $this->jti = $jti; return $this; }
    public function header(string $key, mixed $value): self { $this->headers[$key] = $value; return $this; }

    /**
     * 标记签发为 Refresh Token（添加 typ: 'refresh' 声明）
     */
    public function asRefreshToken(): self
    {
        $this->isRefreshToken = true;
        return $this;
    }

    /**
     * 设置 Access Token 有效期（双令牌模式）
     */
    public function accessTtl(int $seconds): self
    {
        $this->accessTtl = $seconds;
        return $this;
    }

    /**
     * 设置 Refresh Token 有效期（双令牌模式）
     */
    public function refreshTtl(int $seconds): self
    {
        $this->refreshTtl = $seconds;
        return $this;
    }

    /**
     * 启用/禁用 Refresh Token Rotation
     */
    public function rotation(bool $enable = true): self
    {
        $this->rotation = $enable;
        return $this;
    }

    /**
     * 启用/禁用 Refresh Token 指纹绑定（双令牌模式）
     *
     * 启用后 Refresh Token 会包含设备指纹，换票时验证设备一致性。
     */
    public function refreshTokenFingerprint(bool $enable = true): self
    {
        $this->refreshTokenFingerprint = $enable;
        return $this;
    }

    public function issuedBy(): string
    {
        return $this->jwt->getIssuer();
    }

    /**
     * 签发单个 JWT（单令牌模式）
     */
    public function issue(): string
    {
        if ($this->subject === null) {
            throw new \RuntimeException('subject 不能为空');
        }

        // 标准声明后置：iss/sub/iat/nbf/exp/jti 不可被 ->claim()/->claims() 覆盖，
        // 防止外部数据经自定义声明改写身份、签发时间、有效期或 jti
        //（与 Jwt::issue() 的标准声明保护策略保持一致）。
        $claims = array_merge($this->claims, [
            'iss' => $this->issuer ?? $this->jwt->getIssuer(),
            'sub' => $this->subject,
            'iat' => time(),
            'nbf' => $this->notBefore ?? time(),
            'exp' => time() + $this->ttl,
            'jti' => $this->jti ?? bin2hex(random_bytes(16)),
        ]);

        if ($this->audience !== null) {
            $claims['aud'] = $this->audience;
        }
        if ($this->isRefreshToken) {
            $claims['typ'] = Jwt::TYPE_REFRESH;
        }

        return $this->jwt->issueRaw($claims, $this->ttl);
    }

    /**
     * 签发 Token 对（双令牌模式）
     *
     * @return TokenPair
     * @throws \RuntimeException 当 subject 为空时
     */
    public function issuePair(): TokenPair
    {
        if ($this->subject === null) {
            throw new \RuntimeException('subject 不能为空');
        }

        // 在克隆体上应用运行时覆盖：Jwt 实例可能被 Facade / 容器缓存，
        // 直接改属性会在常驻运行时（Swoole/Workerman）跨请求泄漏
        // rotation / audience / 指纹设置。
        $jwt = clone $this->jwt;
        if ($this->rotation !== null) {
            $jwt->setRotation($this->rotation);
        }
        if ($this->refreshTokenFingerprint !== null) {
            $jwt->setRefreshTokenFingerprint($this->refreshTokenFingerprint);
        }
        if ($this->audience !== null) {
            $jwt->setAudience(is_array($this->audience) ? implode(',', $this->audience) : $this->audience);
        }

        return $jwt->issuePair(
            subject: $this->subject,
            claims: $this->claims,
            accessTtl: $this->accessTtl ?? $jwt->getTtl(),
            refreshTtl: $this->refreshTtl ?? $jwt->getRefreshTokenTtl()
        );
    }
}
