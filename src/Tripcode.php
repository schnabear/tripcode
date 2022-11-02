<?php

/**
 * Tripcode - Just another tripcode library
 *
 * @author schnabear <https://schnabear.github.io>
 * @copyright 2018 schnabear
 * @license <http://www.opensource.org/licenses/mit-license.php> MIT
 */

namespace Tripcode;

class Tripcode
{
    /**
     * @var int
     */
    const MAX_UNICODE = 1114111;

    /**
     * @var string
     */
    protected $name = '';

    /**
     * @var string
     */
    protected $key = '';

    /**
     * @var string
     */
    protected $tripcode = '';

    /**
     * @param  string  $string
     * @param  string  $secret
     * @param  int  $limit
     * @return void
     */
    public function __construct($string, $secret = '', $limit = 0)
    {
        $string = str_replace(array('﹟', '＃', '♯'), '#', $string);
        if (preg_match('/^([^#]+)(#)(.+)/us', $string, $matches)) {
            $matches[3] = $limit ? mb_substr($matches[3], 0, $limit) : $matches[3];
            $this->name = $matches[1];
            $this->key = $matches[2] . $matches[3];
            $this->tripcode = $this->process($this->key, $secret);
        } else {
            $this->name = $string;
        }
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getTripcode()
    {
        return $this->tripcode;
    }

    /**
     * Wakaba forbidden unicode checking
     * 
     * @param  string  $dec
     * @param  string  $hex
     * @return bool
     */
    protected function isForbiddenUnicode($dec, $hex)
    {
        // Too long numbers
        if (strlen($dec) > 7 || strlen($hex) > 7) {
            return true;
        }

        $ord = (int) $dec ?: hexdec($hex);
        return ($ord > self::MAX_UNICODE) // Outside unicode range
            || ($ord < 32) // Control characters
            || ($ord >= 0x7f && $ord <= 0x84) // Control characters
            || ($ord >= 0xd800 && $ord <= 0xdfff) // Surrogate code points
            || ($ord >= 0x202a && $ord <= 0x202e) // Text direction
            || ($ord >= 0xfdd0 && $ord <= 0xfdef) // Non-characters
            || ($ord % 0x10000 >= 0xfffe); // Non-characters
    }

    /**
     * Wakaba string decoder
     * 
     * @param  string  $string
     * @param  bool  $use_unicode
     * @return string
     */
    protected function decode($string, $use_unicode = true)
    {
        $string = preg_replace_callback(
            '/&#(?:([0-9]*)|([Xx&])([0-9A-Fa-f]*))([;&])/s', // (&#([0-9]*)([;&])|&#([x&])([0-9a-f]*)([;&]))
            function ($matches) use ($use_unicode) {
                list($full, $dec, $ampex, $hex, $end) = array_pad($matches, 5, "");
                $ord = (int) ($dec ?: hexdec($hex));
                if ($ampex == "&" || $end == "&") {
                    return $full;
                } elseif ($this->isForbiddenUnicode($dec, $hex)) {
                    return "";
                } elseif ($ord == 35 || $ord == 38) {
                    return $full;
                } elseif ($use_unicode || $ord < 128) {
                    mb_substitute_character("none");
                    return mb_convert_encoding("&#" . $ord . ";", "UTF-8", "HTML-ENTITIES");
                } else {
                    return $full;
                }
            },
            $string
        );

        return $string;
    }

    /**
     * Mixed cleanup based mainly on Wakaba and some Kareha, Futaba, Futallaby, and Yotsuba
     * Does not include Yotsuba skip BiDi
     * 
     * @param  string  $string
     * @param  bool  $is_complex
     * @return string
     */
    protected function clean($string, $is_complex = true)
    {
        if (!$is_complex) {
            $string = str_replace('&', '&amp;', $string);
        } else {
            $string = preg_replace_callback(
                '/&(#([0-9]+);|#[Xx]([0-9A-Fa-f]+);|)/s',
                function ($matches) {
                    list($full, $code_point, $dec, $hex) = array_pad($matches, 4, "");
                    if ($code_point == "") {
                        return "&amp;";
                    } elseif ($this->isForbiddenUnicode($dec, $hex)) {
                        return "";
                    } else {
                        return "&{$code_point}";
                    }
                },
                $string
            );
        }

        $string = str_replace(',', '&#44;', $string);
        $string = str_replace('"', '&quot;', $string);
        $string = str_replace('\'', '&#39;', $string);
        $string = str_replace('<', '&lt;', $string);
        $string = str_replace('>', '&gt;', $string);

        // '/\xF0\x9F\x92\x94/&#128148;/'
        // '/[\x{202A}-\x{202E}]//';

        $string = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $string);

        return $string;
    }

    /**
     * Generate NULLBYTE nothing fancy
     * 
     * @param  int  $length
     * @return string
     */
    protected function nullbyte($length)
    {
        return str_repeat("\0", $length);
    }

    /**
     * Wakaba RC4 encrypt with nullbyte key
     * 
     * @param  string  $data
     * @param  int  $length
     * @return string
     */
    protected function encrypt($data, $length)
    {
        $nullbyte = $this->nullbyte($length);
        return openssl_encrypt($data, 'rc4', $nullbyte, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }

    /**
     * Generate some trips for better quads
     * 
     * @param  string  $key
     * @param  string  $secret
     * @return string
     */
    protected function process($key, $secret = '')
    {
        $tripcode = '';
        // Expecting formats #key, ##key, #key#key
        $hash_index_adjustment = (int) ($key[0] == '#');
        $keys = array_pad(mb_split('#', mb_substr($key, $hash_index_adjustment), 2), 2, '');
        $key_normal = $keys[0];
        $key_secure = $keys[1];

        if ($key_normal) {
            mb_substitute_character('none');
            $encode = mb_convert_encoding($this->decode($key_normal), 'SJIS', 'UTF-8');
            $key_normal = $encode ?: $key_normal;
            $key_normal = $this->clean($key_normal);

            // Wakaba uses 'H..' while Futaba uses 'H.'
            $salt = substr($key_normal . 'H..', 1, 2);
            $salt = preg_replace('/[^\.-z]/', '.', $salt);
            $salt = strtr($salt, ':;<=>?@[\\]^_`', 'ABCDEFGabcdef');
            $tripcode .= '!' . substr(crypt($key_normal, $salt), -10);
        }
        if ($key_secure) {
            // TinyIB
            // $tripcode .= '!!' . substr(md5($key_secure . $secret), 2, 10);
            // Yotsuba LEN = 11
            // Shiichan LEN = 15
            // $tripcode .= '!!' . substr(base64_encode(pack("H*", sha1($key_secure . $secret))), 0, 15);
            // wakautils.pl#L725
            $max_length = 255 - strlen($secret);
            if (strlen($key_secure) > $max_length) {
                $key_secure = substr($key_secure, 0, $max_length);
            }
            $secret = $this->encrypt('trip' . $secret, 32);
            $key_secure = $this->encrypt($secret . $key_secure, 6);
            $tripcode .= '!!' . base64_encode($key_secure);
        }

        return $tripcode;
    }
}
