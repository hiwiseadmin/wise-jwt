<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\jwt\exception\JwtException;

/**
 * 非对称签名器密钥校验 Trait
 *
 * 在构造函数中校验私钥和公钥是否为空，避免延迟到签名时才报错。
 */
trait ValidatesKeys
{
    /**
     * 校验非对称密钥对不为空
     *
     * @throws JwtException 当私钥或公钥为空时
     */
    protected function validateKeys(string $privateKey, string $publicKey, string $algorithm): void
    {
        if ($privateKey === '') {
            throw new JwtException("{$algorithm} 私钥不能为空，请设置对应的环境变量");
        }
        if ($publicKey === '') {
            throw new JwtException("{$algorithm} 公钥不能为空，请设置对应的环境变量");
        }
    }
}
