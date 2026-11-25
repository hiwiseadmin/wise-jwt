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
     * 支持短格式和长格式 DER 长度编码。
     *
     * @throws SignatureInvalidException
     */
    protected function derToRaw(string $der, int $partLength): string
    {
        if (strlen($der) < 6) {
            throw new SignatureInvalidException('无效的 DER 签名格式');
        }

        $pos = 0;
        if (ord($der[$pos]) !== 0x30) {
            throw new SignatureInvalidException('DER 签名必须以 SEQUENCE 开头');
        }
        $pos++;

        $this->readDerLength($der, $pos);

        if (!isset($der[$pos]) || ord($der[$pos]) !== 0x02) {
            throw new SignatureInvalidException('DER 签名 R 分量格式错误');
        }
        $pos++;
        $rLen = $this->readDerLength($der, $pos);
        if ($pos + $rLen > strlen($der)) {
            throw new SignatureInvalidException('DER 签名 R 分量越界');
        }
        $r = substr($der, $pos, $rLen);
        $pos += $rLen;

        if (!isset($der[$pos]) || ord($der[$pos]) !== 0x02) {
            throw new SignatureInvalidException('DER 签名 S 分量格式错误');
        }
        $pos++;
        $sLen = $this->readDerLength($der, $pos);
        $s = substr($der, $pos, $sLen);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");
        if (strlen($r) > $partLength || strlen($s) > $partLength) {
            throw new SignatureInvalidException('ECDSA 签名分量超长');
        }
        $r = str_pad($r, $partLength, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $partLength, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * 读取 DER 长度字段（支持短格式和长格式），并推进 $pos 指针
     *
     * - 短格式：0x00–0x7F → 直接返回长度值
     * - 长格式：0x80+ → 低 7 位表示后续字节数，拼接为大整数
     */
    private function readDerLength(string $data, int &$pos): int
    {
        $first = ord($data[$pos++]);
        if ($first < 0x80) {
            return $first;
        }
        $numBytes = $first & 0x7F;
        $len = 0;
        for ($i = 0; $i < $numBytes; $i++) {
            $len = ($len << 8) | ord($data[$pos++]);
        }
        return $len;
    }

    /**
     * Raw (r||s) → DER
     *
     * @throws SignatureInvalidException
     */
    protected function rawToDer(string $raw): string
    {
        if (strlen($raw) < 2 || strlen($raw) % 2 !== 0) {
            throw new SignatureInvalidException('无效的 ECDSA raw 签名长度');
        }

        $partLength = strlen($raw) / 2;
        $r = substr($raw, 0, $partLength);
        $s = substr($raw, $partLength);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        if ($r === '' || $s === '') {
            throw new SignatureInvalidException('ECDSA 签名分量无效');
        }

        if (ord($r[0]) >= 0x80) $r = "\x00" . $r;
        if (ord($s[0]) >= 0x80) $s = "\x00" . $s;

        $rDer = "\x02" . $this->encodeDerLength(strlen($r)) . $r;
        $sDer = "\x02" . $this->encodeDerLength(strlen($s)) . $s;
        $content = $rDer . $sDer;

        return "\x30" . $this->encodeDerLength(strlen($content)) . $content;
    }

    /**
     * 编码 DER 长度字段（短格式 < 0x80；长格式 0x80|字节数 + 大端长度）
     */
    private function encodeDerLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
