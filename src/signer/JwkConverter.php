<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\jwt\exception\JwtException;

/**
 * JWK (JSON Web Key) 格式转换器
 *
 * 支持 PEM ↔ JWK 双向转换，兼容 RSA / EC 密钥类型。
 * 便于与现代身份系统（Auth0、Okta、Keycloak）对接。
 *
 * 注意：暂不支持 Ed25519（OKP）类型，jwkToPublicKey() 传入 kty=OKP 会抛异常。
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7517
 */
class JwkConverter
{
    /**
     * 将 PEM 公钥转换为 JWK 数组
     *
     * @param string $pem     PEM 格式公钥
     * @param string $kid     可选 Key ID
     * @param string $use     可选用途（sig / enc）
     * @return array JWK 数组
     * @throws JwtException 当密钥类型不支持或解析失败时
     */
    public static function publicKeyToJwk(string $pem, string $kid = '', string $use = 'sig'): array
    {
        // 先校验句柄：openssl_pkey_get_public() 对非法 PEM 返回 false，
        // 直接把 false 传给 openssl_pkey_get_details() 会抛 TypeError（而非 JwtException）。
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new JwtException('无法解析 PEM 公钥');
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new JwtException('无法解析 PEM 公钥');
        }

        $jwk = ['kty' => '', 'use' => $use];
        if ($kid !== '') {
            $jwk['kid'] = $kid;
        }

        return match ($details['type']) {
            OPENSSL_KEYTYPE_RSA => self::rsaToJwk($details, $jwk),
            OPENSSL_KEYTYPE_EC  => self::ecToJwk($details, $jwk),
            default             => throw new JwtException('不支持的密钥类型: ' . ($details['type'] ?? 'unknown')),
        };
    }

    /**
     * 将 JWK 数组转换为 PEM 公钥
     *
     * @param array $jwk JWK 数组
     * @return string PEM 公钥
     * @throws JwtException
     */
    public static function jwkToPublicKey(array $jwk): string
    {
        $kty = $jwk['kty'] ?? '';
        if ($kty === '') {
            throw new JwtException('JWK 缺少 kty 字段');
        }

        return match (strtoupper($kty)) {
            'RSA' => self::rsaFromJwk($jwk),
            'EC'  => self::ecFromJwk($jwk),
            default => throw new JwtException("不支持的 JWK 类型: {$kty}"),
        };
    }

    // ── RSA ──

    protected static function rsaToJwk(array $details, array $jwk): array
    {
        $jwk['kty'] = 'RSA';
        $jwk['alg'] = 'RS256';
        $jwk['n']   = self::base64UrlEncode($details['rsa']['n']);
        $jwk['e']   = self::base64UrlEncode($details['rsa']['e']);
        return $jwk;
    }

    protected static function rsaFromJwk(array $jwk): string
    {
        if (!isset($jwk['n'], $jwk['e'])) {
            throw new JwtException('RSA JWK 缺少 n 或 e 字段');
        }

        $n = self::base64UrlDecode($jwk['n']);
        $e = self::base64UrlDecode($jwk['e']);

        $pem = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode(self::packRsaKey($n, $e)), 64, "\n");
        $pem .= "-----END PUBLIC KEY-----\n";

        return self::exportPublicKeyPem($pem, '无法从 JWK 构造 RSA 公钥');
    }

    /**
     * 校验刚构造出的公钥 PEM，并导出规范化 PEM
     *
     * openssl_pkey_export() 仅用于导出私钥，对公钥返回 false 且不写出 $output；
     * 公钥 PEM 必须从 openssl_pkey_get_details() 的 key 字段取。
     *
     * @throws JwtException
     */
    protected static function exportPublicKeyPem(string $pem, string $errorMessage): string
    {
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new JwtException($errorMessage);
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['key'] ?? '') === '') {
            throw new JwtException($errorMessage);
        }

        return $details['key'];
    }

    // ── EC ──

    protected static function ecToJwk(array $details, array $jwk): array
    {
        $jwk['kty'] = 'EC';
        $jwk['crv'] = self::ecCurveName($details['ec']['curve_oid'] ?? '');
        $jwk['x']   = self::base64UrlEncode($details['ec']['x']);
        $jwk['y']   = self::base64UrlEncode($details['ec']['y']);
        return $jwk;
    }

    protected static function ecFromJwk(array $jwk): string
    {
        if (!isset($jwk['crv'], $jwk['x'], $jwk['y'])) {
            throw new JwtException('EC JWK 缺少 crv/x/y 字段');
        }

        $crv = $jwk['crv'];
        $x   = self::base64UrlDecode($jwk['x']);
        $y   = self::base64UrlDecode($jwk['y']);

        return self::exportPublicKeyPem(self::packEcKey($crv, $x, $y), '无法从 JWK 构造 EC 公钥');
    }

    // ── 工具 ──

    protected static function ecCurveName(string $oid): string
    {
        return match ($oid) {
            '1.2.840.10045.3.1.7' => 'P-256',
            '1.3.132.0.34'        => 'P-384',
            '1.3.132.0.35'        => 'P-521',
            default               => $oid,
        };
    }

    /**
     * 将 RSA 模数 + 指数打包为 SubjectPublicKeyInfo（X.509）DER 公钥
     *
     * RSAPublicKey ::= SEQUENCE { INTEGER modulus, INTEGER publicExponent }
     * SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
     */
    protected static function packRsaKey(string $n, string $e): string
    {
        $rsaPublicKey = self::wrapDer(0x30, self::packInteger($n) . self::packInteger($e));
        $bitString = self::wrapDer(0x03, "\x00" . $rsaPublicKey);
        // AlgorithmIdentifier: id-rsaEncryption (1.2.840.113549.1.1.1) + NULL
        $algId = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

        return self::wrapDer(0x30, $algId . $bitString);
    }

    /**
     * 将 EC 参数打包为 SubjectPublicKeyInfo（X.509）PEM 公钥
     */
    protected static function packEcKey(string $curve, string $x, string $y): string
    {
        [$oid, $size] = match ($curve) {
            'P-256' => ['2a8648ce3d030107', 32],
            'P-384' => ['2b81040022', 48],
            'P-521' => ['2b81040023', 66],
            default => throw new JwtException("不支持的 EC 曲线: {$curve}"),
        };

        // JWK 的 x/y 为定长曲线坐标，补足前导零后再拼未压缩点格式 0x04||x||y
        $point = "\x04"
            . str_pad($x, $size, "\x00", STR_PAD_LEFT)
            . str_pad($y, $size, "\x00", STR_PAD_LEFT);

        $algId = self::wrapDer(
            0x30,
            "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" // OID: id-ecPublicKey
            . "\x06" . pack('H*', self::encodeLength(strlen($oid) / 2)) . pack('H*', $oid)
        );
        $bitString = self::wrapDer(0x03, "\x00" . $point);

        $der = self::wrapDer(0x30, $algId . $bitString);

        return "-----BEGIN PUBLIC KEY-----\n" .
               chunk_split(base64_encode($der), 64, "\n") .
               "-----END PUBLIC KEY-----\n";
    }

    /**
     * DER TLV 包装：tag + 长度 + 内容（长度字段复用 encodeLength 的十六进制输出）
     */
    protected static function wrapDer(int $tag, string $content): string
    {
        return chr($tag) . pack('H*', self::encodeLength(strlen($content))) . $content;
    }

    /**
     * DER INTEGER：最小长度编码，最高位为 1 时补 0x00 符号前缀
     */
    protected static function packInteger(string $bin): string
    {
        $bin = ltrim($bin, "\x00");
        if ($bin !== '' && (ord($bin[0]) & 0x80) !== 0) {
            $bin = "\x00" . $bin;
        }

        return self::wrapDer(0x02, $bin);
    }

    protected static function encodeLength(int $length): string
    {
        if ($length < 128) {
            return sprintf('%02X', $length);
        }
        // 长格式
        $lenBytes = dechex($length);
        if (strlen($lenBytes) % 2 !== 0) {
            $lenBytes = '0' . $lenBytes;
        }
        return sprintf('%02X', 0x80 | (strlen($lenBytes) / 2)) . strtoupper($lenBytes);
    }

    protected static function base64UrlEncode(string $data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    protected static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(str_replace(['-', '_'], ['+', '/'], $data));
        return $decoded !== false ? $decoded : '';
    }
}
