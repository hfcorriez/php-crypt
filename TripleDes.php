<?php

namespace CodeGun\Util\Crypt;

class TripleDes
{
    public static function encrypt($input, $key, $iv)
    {
        $key = pack('H48', $key);
        $iv = pack('H16', $iv);

        $block_size = mcrypt_get_block_size('tripledes', 'ecb');
        $padding_char = $block_size - (strlen($input) % $block_size);
        return mcrypt_encrypt(MCRYPT_3DES, $key, str_repeat(chr($padding_char), $padding_char), MCRYPT_MODE_CBC, $iv);
    }

    public static function decrypt($input, $key, $iv)
    {
        $key = pack('H48', $key);
        $iv = pack('H16', $iv);
        $result = mcrypt_decrypt(MCRYPT_3DES, $key, $input, MCRYPT_MODE_CBC, $iv);
        $end = ord(substr($result, -1));
        $out = substr($result, 0, -$end);
        return $out;
    }
}