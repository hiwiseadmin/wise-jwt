<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\jwt\exception\SignatureInvalidException;

/**
 * ECDSA DER ↔ Raw 签名格式转换
 *
 * OpenSSL 以 DER 格式生成 ECDSA 签名，JWT 规范要求 raw (r||s) 格式。
 * 此 trait 提供两种格式间的双向转换。
 */
trait EcdsaDerTrait
{
    /**
     * DER → Raw (r||s)
     *
     * @throws SignatureInvalidException
     */
    protected function derToRaw(string $der, int $partLength): string
    {
        if (strlen($der) < 6) {
            throw new SignatureInvalidException('无效的 DER 签名格式');
        }

        // 解析 DER 编码的 ECDSA 签名
        $offset = 4; // skip 0x30, total_len, 0x02, r_len
        $rLen = ord($der[2]);
        if ($offset + $rLen > strlen($der)) {
            throw new SignatureInvalidException('DER 签名 R 分量越界');
        }
        $r = substr($der, $offset, $rLen);
        $offset += $rLen + 2; // skip r + 0x02 + s_len
        $s = substr($der, $offset);

        // 补齐到指定长度
        if (strlen($r) < $partLength) {
            $r = str_repeat("\x00", $partLength - strlen($r)) . $r;
        }
        if (strlen($s) < $partLength) {
            $s = str_repeat("\x00", $partLength - strlen($s)) . $s;
        }
        return $r . $s;
    }

    /**
     * Raw (r||s) → DER
     *
     * @throws SignatureInvalidException
     */
    protected function rawToDer(string $raw): string
    {
        $partLength = strlen($raw) / 2;
        $r = substr($raw, 0, $partLength);
        $s = substr($raw, $partLength);

        // 去除前导零
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        if ($r === '' || $s === '') {
            throw new SignatureInvalidException('ECDSA 签名分量无效');
        }

        // 如果首字节 >= 0x80，需要在前面加 0x00
        if (ord($r[0]) >= 0x80) $r = "\x00" . $r;
        if (ord($s[0]) >= 0x80) $s = "\x00" . $s;

        $rLen = chr(strlen($r));
        $sLen = chr(strlen($s));
        $totalLen = chr(4 + strlen($r) + strlen($s));

        return "\x30" . $totalLen . "\x02" . $rLen . $r . "\x02" . $sLen . $s;
    }
}
