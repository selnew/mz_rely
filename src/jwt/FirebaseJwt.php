<?php
namespace mzrely\jwt;

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

/**
 * JWT认证封装：设置header中Authorization为token值
 * @author Mirze <mirzeAdv@163.com>
 * 官网：
 *      https://jwt.io/
 *      https://github.com/firebase/php-jwt
 * 引入：[前提依赖]
 *      composer require firebase/php-jwt [php > 7.2+]
 *      composer require paragonie/sodium_compat [php < 7.2]
 * 使用：
 *      composer require mirze/mz_rely
 * 例：
 *  $data = [
        'uid' => 9,
        'name' => 'Mirze',
    ];
    // $jwt = new \sdk\FirebaseJwt();
    $jwt = new \mzrely\jwt\FirebaseJwt();
    $token = $jwt->genToken($data,7200);
    $res = $jwt->parseToken($token,1);
 * 
 * @time 2022-12-23 更新时间
 * 
 *  预定义（Registered）
        iss (issuer)：签发人
        sub (subject)：主题
        aud (audience)：受众
        exp (expiration time)：过期时间
        nbf (Not Before)：生效时间，在此之前是无效的
        iat (Issued At)：签发时间
        jti (JWT ID)：编号，jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
 * 
 */
class FirebaseJwt
{
    // JWT使用KEY
    protected $key = "api-jwt";
    protected $alg = "HS256";

    public function __construct()
    {
    }

    // 自定义KEY
    public function initKey($key='')
    {
        if(empty($key) || !is_string($key)) return true;

        $this->key = trim($key);
        return $this->key;
    }

    /**
     * Discuz经典加解密算法：
     *
     * @param string $string        明文 或 密文
     * @param string $operation     类型：ENCODE 加密 DECODE 解密
     * @param string $key           密匙
     * @param integer $expiry       密文有效期
     * @param boolean $url_safe     返回字符串是否url安全
     * @return void
     * @Author Mirze
     * @DateTime 2022-12-23
     */
    function authCode($string='', $operation = 'DECODE', $key = 'mzjwt', $expiry = 0, $url_safe = true)
    {
        // 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙
        // 加入随机密钥，可以令密文无任何规律，即便是原文和密钥完全相同，加密结果也会每次不同，增大破解难度。
        // 取值越大，密文变动规律越大，密文变化 = 16 的 $ckey_length 次方
        // 当此值为 0 时，则不产生随机密钥
        $ckey_length = 4;

        // 密匙
        $key = md5($key);

        // 密匙a会参与加解密
        $keya = md5(substr($key, 0, 16));
        // 密匙b会用来做数据完整性验证
        $keyb = md5(substr($key, 16, 16));
        // 密匙c用于变化生成的密文
        $string = $operation == 'DECODE' && $url_safe ? rawurldecode($string) : $string;
        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()), -$ckey_length)) : '';
        // 参与运算的密匙
        $cryptkey = $keya . md5($keya . $keyc);
        $key_length = strlen($cryptkey);
        // 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyb(密匙b)，解密时会通过这个密匙验证数据完整性
        // 如果是解码的话，会从第$ckey_length位开始，因为密文前$ckey_length位保存 动态密匙，以保证解密正确
        $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        $string_length = strlen($string);
        $result = '';
        $box = range(0, 255);
        $rndkey = array();
        // 产生密匙簿
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        // 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上并不会增加密文的强度
        for ($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        // 核心加解密部分
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            // 从密匙簿得出密匙进行异或，再转成字符
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        if ($operation == 'DECODE') {
            // substr($result, 0, 10) == 0 验证数据有效性
            // substr($result, 0, 10) - time() > 0 验证数据有效性
            // substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16) 验证数据完整性
            // 验证数据有效性，请看未加密明文的格式
            if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
                return substr($result, 26);
            } else {
                return '';
            }
        } else {
            // 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因
            // 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码
            // rawurldecode() 不会把加号（'+'）解码为空格，而 urldecode() 可以。
            $result = $keyc . str_replace('=', '', base64_encode($result));
            if ($url_safe) {
                return rawurlencode($result);
            }
            return $result;
        }
    }
    
    /**
     * 生成JWT
     *
     * @param array $data       数据集：用户数据
     * @param integer $exp      过期时长：秒
     * @param string $alg       使用JWT算法：
     * @return void
     * @Author Mirze
     * @DateTime 2022-12-23
     */
    public function genToken($data=[], $exp=0, $alg='')
    {
        if(empty($data)) return '';

        $time = time();

        $payload['iss'] = 'MZ'; // 签发人
        // $payload['aud'] = ''; // 受众
        $payload['iat'] = $time; // 签发时间
        $payload['nbf'] = $time; // 生效时间
        $payload['exp'] = ($exp > 0) ? $time + $exp : $time; // 过期时间
        // $payload['data'] = $data;
        
        $alg = empty($alg) ? $this->alg : $alg; // JWT算法
        $jwt = '';
        try {
            // 数据加密
            $json = json_encode($data);
            $auth = $this->authCode($json, 'ENCODE', $this->key);
            $payload['data'] = $auth;

            // JWT
            $jwt = JWT::encode($payload, $this->key, $alg);
        } catch (\Exception $e) { }
        return $jwt;
    }

    /**
     * 解析JWT数据：返回用户数据集
     *
     * @param string $jwt           jwt字符串
     * @param integer $checkExp     是否校验过期exp：默认不校验
     * @param string $alg           使用JWT算法：
     * @return void
     * @Author Mirze
     * @DateTime 2022-12-23
     */
    public function parseToken($jwt='', $checkExp=0, $alg='')
    {
        if(empty($jwt)) return [];
        $alg = empty($alg) ? $this->alg : $alg; // JWT算法

        $result = [];
        try {
            // $data = JWT::decode($jwt, $this->key, $alg);
            $data = JWT::decode($jwt, new Key($this->key, $alg));

            $enData = empty($data->data) ? '' : $data->data; // 加密数据
            $deData = $this->authCode($enData, 'DECODE', $this->key); // 解密后数据
            // 校验过期
            if($checkExp) {
                $time = time();
                $exp = empty($data->exp) ? 0 : $data->exp; // 0 长期
                if($exp > 0 && $exp < $time) return []; // 过期
            }
            $result = json_decode($deData, true);
        } catch (\Exception $e) { }
        return $result;
    }


}