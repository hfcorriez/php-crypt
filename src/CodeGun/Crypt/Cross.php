<?php

namespace CodeGun\Crypt;

class Cross
{
    /**
     * EnCrypt
     *
     * @param string $str
     * @param        $key
     * @return string
     */
    public static function encrypt($str, $key)
    {
        $key_length = strlen($key);
        $length = strlen($str);
        $byte = array();
        $result = substr($str, 0, 1);

        for ($i = 0; $i < $length; $i++)
            $byte[$i] = self::char2byte($str{$i});

        for ($i = 1; $i < $length; $i++) {
            $byte[$i] = ($byte[$i] ^ $byte[$i - 1]) + self::char2byte($key{$i % $key_length});
            $result .= self::byte2char($byte[$i]);
        }
        return $result;
    }

    /**
     * DeCrypt
     *
     * @param string $str
     * @param        $key
     * @return string
     */
    public static function decrypt($str, $key)
    {
        $key_length = strlen($key);
        $length = strlen($str);
        $byte = array();
        $result = '';

        for ($i = 0; $i < $length; $i++)
            $byte[$i] = self::char2byte($str{$i});

        for ($i = $length - 1; $i > 0; $i--) {
            $byte[$i] = ($byte[$i] - self::char2byte($key{$i % $key_length})) ^ $byte[$i - 1];
            $result = self::byte2char($byte[$i]) . $result;
        }
        $result = substr($str, 0, 1) . $result;
        return $result;
    }

    /**
     * Convert char to byte.
     *
     * @param string $char
     * @return int
     */
    private static function char2byte($char)
    {
        return (int)array_pop(unpack('c', $char));
    }

    /**
     * Convert byte to char
     *
     * @param int $byte
     * @return string
     */
    private static function byte2char($byte)
    {
        return pack('c', $byte);
    }
}