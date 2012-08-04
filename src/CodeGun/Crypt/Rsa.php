<?php

namespace CodeGun\Crypt;

define("BCCOMP_LARGER", 1);

class Rsa
{
    public static function encrypt($message, $public_key, $modulus, $key_length)
    {
        $padded = self::add_PKCS1_padding($message, true, $key_length / 8);
        $number = self::binary_to_number($padded);
        $encrypted = self::pow_mod($number, $public_key, $modulus);
        $result = self::number_to_binary($encrypted, $key_length / 8);

        return $result;
    }

    public static function decrypt($message, $private_key, $modulus, $key_length)
    {
        $number = self::binary_to_number($message);
        $decrypted = self::pow_mod($number, $private_key, $modulus);
        $result = self::number_to_binary($decrypted, $key_length / 8);

        return self::remove_PKCS1_padding($result, $key_length / 8);
    }

    public static function sign($message, $private_key, $modulus, $key_length)
    {
        $padded = self::add_PKCS1_padding($message, false, $key_length / 8);
        $number = self::binary_to_number($padded);
        $signed = self::pow_mod($number, $private_key, $modulus);
        $result = self::number_to_binary($signed, $key_length / 8);

        return $result;
    }

    public static function verify($message, $public_key, $modulus, $key_length)
    {
        return self::decrypt($message, $public_key, $modulus, $key_length);
    }

    private static function pow_mod($p, $q, $r)
    {
        // Extract powers of 2 from $q
        $factors = array();
        $div = $q;
        $power_of_two = 0;
        while (bccomp($div, "0") == BCCOMP_LARGER) {
            $rem = bcmod($div, 2);
            $div = bcdiv($div, 2);

            if ($rem) array_push($factors, $power_of_two);
            $power_of_two++;
        }

        // Calculate partial results for each factor, using each partial result as a
        // starting point for the next. This depends of the factors of two being
        // generated in increasing order.
        $partial_results = array();
        $part_res = $p;
        $idx = 0;
        foreach ($factors as $factor) {
            while ($idx < $factor) {
                $part_res = bcpow($part_res, "2");
                $part_res = bcmod($part_res, $r);

                $idx++;
            }

            array_push($partial_results, $part_res);
        }

        // Calculate final result
        $result = "1";
        foreach ($partial_results as $part_res) {
            $result = bcmul($result, $part_res);
            $result = bcmod($result, $r);
        }

        return $result;
    }

    private static function add_PKCS1_padding($data, $isPublicKey, $block_size)
    {
        $pad_length = $block_size - 3 - strlen($data);

        if ($isPublicKey) {
            $block_type = "\x02";

            $padding = "";
            for ($i = 0; $i < $pad_length; $i++) {
                $rnd = mt_rand(1, 255);
                $padding .= chr($rnd);
            }
        } else {
            $block_type = "\x01";
            $padding = str_repeat("\xFF", $pad_length);
        }

        return "\x00" . $block_type . $padding . "\x00" . $data;
    }

    private static function remove_PKCS1_padding($data, $block_size)
    {
        assert(strlen($data) == $block_size);
        $data = substr($data, 1);

        // We cannot deal with block type 0
        if ($data{0} == '\0')
            die("Block type 0 not implemented.");

        // Then the block type must be 1 or 2
        assert(($data{0} == "\x01") || ($data{0} == "\x02"));

        // Remove the padding
        $offset = strpos($data, "\0", 1);
        return substr($data, $offset + 1);
    }

    private static function binary_to_number($data)
    {
        $base = "256";
        $radix = "1";
        $result = "0";

        for ($i = strlen($data) - 1; $i >= 0; $i--) {
            $digit = ord($data{$i});
            $part_res = bcmul($digit, $radix);
            $result = bcadd($result, $part_res);
            $radix = bcmul($radix, $base);
        }

        return $result;
    }

    private static function number_to_binary($number, $block_size)
    {
        $base = "256";
        $result = "";

        $div = $number;
        while ($div > 0) {
            $mod = bcmod($div, $base);
            $div = bcdiv($div, $base);

            $result = chr($mod) . $result;
        }

        return str_pad($result, $block_size, "\x00", STR_PAD_LEFT);
    }

}

?>