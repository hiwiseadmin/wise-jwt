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

        // 解析 DER SEQUENCE (0x30)
        $pos = 0;
        if (ord($der[$pos]) !== 0x30) {
            throw new SignatureInvalidException('DER 签名必须以 SEQUENCE 开头');
        }
        $pos++;

        // 解析 SEQUENCE 总长度（支持长格式）
        $this->readDerLength($der, $pos);

        // 解析 INTEGER r (0x02)
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

        // 解析 INTEGER s (0x02)
        if (!isset($der[$pos]) || ord($der[$pos]) !== 0x02) {
            throw new SignatureInvalidException('DER 签名 S 分量格式错误');
        }
        $pos++;
        $sLen = $this->readDerLength($der, $pos);
        $s = substr($der, $pos, $sLen);

        // 归一到固定长度：DER 中 r/s 为有符号整数，高位为 1 时（最高位为符号位）
        // 会额外带一个 0x00 前缀，必须先剥离再左补零；否则 raw 签名会多出字节，
        // 不符合 RFC 7515 的定长 r||s 要求。
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
        // 防御：raw 签名必须为偶数长度，否则分量切分会得到小数并触发 TypeError
        if (strlen($raw) < 2 || strlen($raw) % 2 !== 0) {
            throw new SignatureInvalidException('无效的 ECDSA raw 签名长度');
        }

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

        // DER 长度字段：>= 0x80 必须使用长格式，否则 ES512（SEQUENCE 内容 136 字节）
        // 会产生非法编码，openssl_verify 必然失败。
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
