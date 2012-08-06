<?php

namespace CodeGun\Crypt;

class TripleDes
{
    public static function encrypt($input, $key, $iv)
    {
        $key = pack('H48', $key);
        $iv = pack('H16', $iv);

        $src_data = $input;
        $block_size = mcrypt_get_block_size('tripledes', 'ecb');
        $padding_char = $block_size - (strlen($input) % $block_size);
        $src_data .= str_repeat(chr($padding_char), $padding_char);
        return mcrypt_encrypt(MCRYPT_3DES, $key, $src_data, MCRYPT_MODE_ECB, $iv);
    }

    public static function decrypt($input, $key, $iv)
    {
        $key = pack('H48', $key);
        $iv = pack('H16', $iv);
        $result = mcrypt_decrypt(MCRYPT_3DES, $key, $input, MCRYPT_MODE_ECB, $iv);
        $end = ord(substr($result, -1));
        $out = substr($result, 0, -$end);
        return $out;
    }
}