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
 * @time 2022-01-15 更新时间
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

    // public function __construct()
    // {
    // }

    // 自定义KEY
    public function initKey($key='')
    {
        if(empty($key) || !is_string($key)) return true;

        $this->key = trim($key);
        return $this->key;
    }

    /**
     * [genToken description]
     * @param  [type] $data [description]
     * @return [type]       [description]
     * @author Mirze <2019-04-08>
     */
    public function genToken($data=[], $exp=0, $alg='')
    {
        if(empty($data)) return '';

        $time = time();

        // $data['iss'] = 'MZ'; // 签发人
        // $data['aud'] = ''; // 受众
        // $data['iat'] = $time; // 签发时间

        $data['nbf'] = $time; // 生效时间
        $data['exp'] = ($exp > 0) ? $time + $exp : $time; // 过期时间

        $json = json_encode($data);

        $alg = empty($alg) ? $this->alg : $alg;

        try {
            $auth = $this->authDES($json, 'ENCODE', $this->key);

            $jwt = JWT::encode($auth, $this->key, $alg);
            return $jwt;
        } catch (\Exception $e) {
        }
        return '';
    }

    /**
     * 解析JWT结果
     * @param  string  $jwt      前端返回token串
     * @param  integer $checkExp 校验过期时间：true/1 校验
     * @param  array   $hs       算法：默认HS256
     * @return array             [description]
     * @author Mirze <2019-04-08>
     */
    public function parseToken($jwt='', $checkExp=0, $alg='')
    {
        if(empty($jwt)) return [];
        $alg = empty($alg) ? $this->alg : $alg;

        try {
            // $data = JWT::decode($jwt, $this->key, $alg);
            $data = JWT::decode($jwt, new Key($this->key, $alg));
        } catch (\Exception $e) {
            return [];
        }

        $data = $this->authDES($data, 'DECODE', $this->key);

        $data = json_decode($data,true);

        // 校验过期
        if($checkExp) {
            if(empty($data['exp'])) return [];

            $time = time();
            if($time > $data['exp']) return [];
        }

        return $data;
    }

    /**
     * 加解密
     * @param  string  $string    字符串
     * @param  string  $operation 类型：ENCODE 加密 DECODE 解密
     * @param  string  $key       私钥
     * @param  integer $expiry    有效时长
     * @return [type]             [description]
     * @author Mirze <2019-04-08>
     */
    public function authDES($string='', $operation = 'DECODE', $key = '', $expiry = 0) {
        $operation = strtoupper($operation);

        // 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙   
        $ckey_length = 4;

        // 密匙   
        $key = md5($key ? $key : 'jwtkey');   
           
        // 密匙a会参与加解密   
        $keya = md5(substr($key, 0, 16));   
        // 密匙b会用来做数据完整性验证   
        $keyb = md5(substr($key, 16, 16));   
        // 密匙c用于变化生成的密文   
        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()), -$ckey_length)) : '';   
        // 参与运算的密匙   
        $cryptkey = $keya.md5($keya.$keyc);   
        $key_length = strlen($cryptkey);   
        // 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyb(密匙b)， 
        //解密时会通过这个密匙验证数据完整性   
        // 如果是解码的话，会从第$ckey_length位开始，因为密文前$ckey_length位保存 动态密匙，以保证解密正确   
        $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;   
        $string_length = strlen($string);   
        $result = '';   
        $box = range(0, 255);   
        $rndkey = array();   
        // 产生密匙簿   
        for($i = 0; $i <= 255; $i++) {   
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);   
        }   
        // 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上对并不会增加密文的强度   
        for($j = $i = 0; $i < 256; $i++) {   
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;   
            $tmp = $box[$i];   
            $box[$i] = $box[$j];   
            $box[$j] = $tmp;   
        }   
        // 核心加解密部分   
        for($a = $j = $i = 0; $i < $string_length; $i++) {   
            $a = ($a + 1) % 256;   
            $j = ($j + $box[$a]) % 256;   
            $tmp = $box[$a];   
            $box[$a] = $box[$j];   
            $box[$j] = $tmp;   
            // 从密匙簿得出密匙进行异或，再转成字符   
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));   
        }   
        if($operation == 'DECODE') {  
            // 验证数据有效性，请看未加密明文的格式   
            if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {   
                return substr($result, 26);   
            } else {   
                return '';   
            }   
        } else {   
            // 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因   
            // 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码   
            return $keyc.str_replace('=', '', base64_encode($result));   
        }   
    }



}