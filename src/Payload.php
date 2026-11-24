<?php
declare(strict_types=1);

namespace wise\jwt;

/**
 * Payload 值对象 — RFC 7519 标准声明
 */
class Payload
{
    public function __construct(
        public readonly string $issuer,
        public readonly string|int $subject,
        public readonly ?string $audience,
        public readonly int $issuedAt,
        public readonly int $notBefore,
        public readonly int $expiration,
        public readonly string $jti,
        public readonly array $customClaims = []
    ) {}

    public function toArray(): array
    {
        $data = [
            'iss' => $this->issuer,
            'sub' => $this->subject,
            'iat' => $this->issuedAt,
            'nbf' => $this->notBefore,
            'exp' => $this->expiration,
            'jti' => $this->jti,
        ];
        if ($this->audience !== null) {
            $data['aud'] = $this->audience;
        }
        return array_merge($data, $this->customClaims);
    }

    public static function fromArray(array $data): self
    {
        $standard = ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti'];
        $customClaims = array_diff_key($data, array_flip($standard));
        return new self(
            $data['iss'] ?? '',
            $data['sub'] ?? '',
            $data['aud'] ?? null,
            (int) ($data['iat'] ?? 0),
            (int) ($data['nbf'] ?? 0),
            (int) ($data['exp'] ?? 0),
            $data['jti'] ?? '',
            $customClaims
        );
    }
}
