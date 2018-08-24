<?php
namespace Aquaz\Wechat;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class Wechat
{
    protected $app_id;              // 微信应用ID
    protected $app_secret;          // 微信应用密钥
    protected $mch_id;              // 微信商户ID
    protected $mch_key;             // 微信商户key
    protected $access_token;        // 微信应用全局access_token
    protected $api_params;          // 待请求参数
    protected $api_url;             // 待请求接口地址

    public $debug;                  // 是否开启调试模式
    public $uri_authorize = 'https://open.weixin.qq.com/connect/oauth2/authorize?';
    public $uri_oauth2_token = 'https://api.weixin.qq.com/sns/oauth2/access_token?';
    public $uri_user_info = 'https://api.weixin.qq.com/sns/userinfo?';
    public $uri_template_msg = 'https://api.weixin.qq.com/cgi-bin/message/template/send';
    public $uri_cgi_token = 'https://api.weixin.qq.com/cgi-bin/token';
    public $uri_order = 'https://api.mch.weixin.qq.com/pay/unifiedorder';
    public $uri_tickets = 'https://api.weixin.qq.com/cgi-bin/ticket/getticket';

    public function __construct()
    {
        $this->debug      = config('aquaz-wechat.debug');
        $this->app_id     = config('aquaz-wechat.app_id');
        $this->app_secret = config('aquaz-wechat.app_secret');
        $this->getAccessToken();
    }

    /**
     * 获取全局token
     */
    private function getAccessToken($refresh = false)
    {
        $token_cache_key = 'aquaz_wechat_access_token';
        $access_token = Cache::get($token_cache_key);
        if (empty($access_token) || $refresh) {
            $this->api_url = $this->uri_cgi_token;
            $this->api_params = [
                'grant_type' => 'client_credential',
                'appid'      => $this->app_id,
                'secret'     => $this->app_secret
            ];
            $res = $this->curlCommon();
            if(!empty($res->errcode)){
                switch ($res->errcode){
                    case 40001:
                        return $this->getAccessToken(true); //获取access_token时AppSecret错误，或者access_token无效
                        break;
                    case 40014:
                        return $this->getAccessToken(true); //不合法的access_token
                        break;
                    case 42001:
                        return $this->getAccessToken(true); //access_token超时
                        break;
                    case 45009:
                        return "接口调用超过限制：".$res->errmsg;
                        break;
                    case 41001:
                        return "缺少access_token参数：".$res->errmsg;
                        break;
                    default:
                        return $res->errmsg; //其他错误
                        break;
                }
            }
            $access_token = $res->access_token;
            if ($access_token) {
                Cache::put($token_cache_key, $access_token, 110);  // 缓存110分钟
            }
        }
        return $access_token;
    }

    /**
     * 设置请求参数
     */
    public function setParams($params=[])
    {
        $this->api_params = collect($params)->toArray();
    }

    /**
     * 记录调试日志
     */
    public function aquazLog($log_title, $data, $levels='debug')
    {
        if($this->debug){
            Log::$levels($log_title, collect($data)->toArray());
        }
    }

    /**
     * curl请求方法
     * @param int $post 是否post
     * @return mixed
     */
    public function curlCommon($post = 0)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $this->api_url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($curl, CURLOPT_POST, $post);
        if (!empty($this->api_params)){
            curl_setopt($curl, CURLOPT_POSTFIELDS, $this->api_params);
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($curl);
        curl_close($curl);

        $this->aquazLog(__CLASS__, [$this->api_url, $this->api_params, json_decode($output, true)]);
        return json_decode($output);
    }

    /*
     * 生成随机字符串
     */
    public function createNonceStr($length = 16)
    {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    /**
     * 获取微信OAuth2授权链接
     * @param $redirect_uri 跳转链接
     * @param $scope 授权类型（snsapi_userinfo：获取用户信息， snsapi_base:静默授权）
     * @param string $state
     * @return string
     */
    public function authorizeUrl($redirect_uri, $scope, $state = 'STATE'){
        $param = [
            'appid'         => $this->app_id,
            'redirect_uri'  => urlencode($redirect_uri),
            'response_type' => 'code',
            'scope'         => $scope,
            'state'         => $state
        ];
        return $this->uri_authorize.http_build_query($param)."#wechat_redirect";
    }

    /**
     * 获取OAuth2授权access_token
     * @param string $code 通过get_authorize_url获取到的code
     */
    public function oauth2Token($code = '')
    {
        $this->api_url    = $this->uri_oauth2_token;
        $this->api_params = [
            'appid'      => $this->app_id,
            'secret'     => $this->app_secret,
            'code'       => $code,
            'grant_type' => 'authorization_code'
        ];
        return $this->curlCommon();
    }

    /**
     * 获取用户基础信息
     * @param $values
     * @return mixed
     */
    public function user_info($access_token, $app_id, $lang='zh_CN')
    {
        $this->api_url    = $this->uri_user_info;
        $this->api_params = [
            'access_token'=> $access_token,
            'openid'      => $app_id,
            'lang'        => $lang
        ];
        return $this->curlCommon();
    }

    /**
     * 发送微信模板消息
     * @param $info
     * @param bool $refresh
     * @param int $max
     * @return mixed
     */
    public function sendTemplateMsg($info, $refresh = false, $max = 0, $color = '#173177')
    {
        $this->api_url    = $this->uri_template_msg."?access_token={$this->access_token}";
        $this->api_params = [
            "touser"        => $info['open_id'],
            "template_id"   => $info['template_id'],
            "url"           => $info['url'],
            "data"=>[
                "first" =>[
                    "value" => isset($info['first'])?$info['first']:"",
                    "color" => $color
                ],
                "keyword1" =>[
                    "value" => isset($info['keyword1'])?$info['keyword1']:"",
                    "color" => $color
                ],
                "keyword2" =>[
                    "value" => isset($info['keyword2'])?$info['keyword2']:"",
                    "color" => $color
                ],
                "keyword3" =>[
                    "value" => isset($info['keyword3'])?$info['keyword3']:"",
                    "color" => $color
                ],
                "keyword4" =>[
                    "value" => isset($info['keyword4'])?$info['keyword4']:"",
                    "color" => $color
                ],
                "remark" =>[
                    "value" => isset($info['remark'])?$info['remark']:"",
                    "color" => $color
                ],
            ]
        ];
        $result = $this->curlCommon(1);
        if($result->errcode == 40001 && $max < 3){
            //token无效 刷新后继续请求
            $max++;
            return $this->sendTemplateMsg($info, true, $max, $color);
        }
        return $result;
    }

    /**
     * 输出xml字符
     * @throws WxPayException
     *
     */
    public function toXml()
    {
        if (! is_array($this->api_params) || count($this->api_params) <= 0) {
            throw new \Exception("数组数据异常！");
        }
        $xml = "<xml>";
        foreach ($this->api_params as $key => $val) {
            if (is_numeric($val)) {
                $xml .= "<" . $key . ">" . $val . "</" . $key . ">";
            } else {
                $xml .= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
            }
        }
        $xml .= "</xml>";
        return $xml;
    }

    /**
     * 将xml转为array
     *
     * @param string $xml
     */
    public function fromXml($xml)
    {
        if (! $xml) {
            throw new \Exception("xml数据异常！");
        }
        // 将XML转为array
        // 禁止引用外部xml实体
        libxml_disable_entity_loader(true);
        $this->api_params = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
        return $this->api_params;
    }


    /**
     * 生成签名
     * @return
     */
    public function makeSign()
    {
        // 签名步骤一：按字典序排序参数
        ksort($this->api_params);
        $buff = "";
        foreach ($this->api_params as $k => $v) {
            if ($k != "sign" && $v != "" && ! is_array($v)) {
                $buff .= $k . "=" . $v . "&";
            }
        }
        $buff = trim($buff, "&");
        $string = $buff;
        // 签名步骤二：在string后加入KEY
        $string = $string . "&key=" . $this->key;
        // 签名步骤三：MD5加密
        $string = md5($string);
        // 签名步骤四：所有字符转为大写
        $result = strtoupper($string);
        return $result;
    }

    /**
     * 响应微信回调
     * @param bool $state
     * @return string
     */
    public function notifyesult($state = false)
    {
        if($state){
            $str = '<xml>';
            $str .= '<return_code><![CDATA[SUCCESS]]></return_code>';
            $str .= '<return_msg><![CDATA[OK]]></return_msg>';
            $str .= '</xml>';
        }else{
            $str = '<xml>';
            $str .= '<return_code><![CDATA[FAIL]]></return_code>';
            $str .= '<return_msg><![CDATA[FAIL]]></return_msg>';
            $str .= '</xml>';
        }
        echo $str;
        exit;
    }

    /**
     * 统一下单
     * @return array
     * @throws \Exception
     */
    public function charge()
    {
        $this->api_url = $this->uri_order;
        $this->api_params['sign'] = $this->makeSign();
        $param = $this->api_params;
        $this->api_params = $this->toXml();
        $xml = $this->curlCommon();
        $result = $this->fromXml($xml);

        if($result['return_code'] == "SUCCESS"){
            // H5签名参数
            $this->api_params = [
                'appId'     => $result["appid"],
                'nonceStr'  => $result["nonce_str"],
                'package'   => "prepay_id=" . $result["prepay_id"],
                'timeStamp' => time(),
                'signType'  => "MD5"
            ];
            $sign_new = $this->MakeSign();

            $res = array();
            $res["prepay_id"]    = $result["prepay_id"];
            $res["nonce_str"]    = $result["nonce_str"];
            $res["appid"]        = $param["appid"];
            $res["partnerid"]    = $param['mch_id'];
            $res["package"]      = $param['package'];
            $res["out_trade_no"] = $param['order_no'];
            $res["total_fee"]    = $param['total_fee'];
            $res["sign"]         = $sign_new;
            $res["timestamp"]    = time();
            return $res;
        }else{
            throw new \Exception($result['return_msg']);
        }
    }

    /*
     * 获取分享所需的参数
     */
    public function sharePackage($url)
    {
        $jsapiTicket = $this->jsApiTicket();

        $timestamp = time();
        $nonceStr = $this->createNonceStr();

        // 这里参数的顺序要按照 key 值 ASCII 码升序排序
        $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";
        $signature = sha1($string);

        $signPackage = array(
            "appId"     => $this->app_id,
            "nonceStr"  => $nonceStr,
            "timestamp" => $timestamp,
            "url"       => $url,
            "signature" => $signature,
            "rawString" => $string
        );
        return $signPackage;
    }

    /**
     * 获取js接口票据
     * @param bool $refresh
     * @return mixed
     */
    public function jsApiTicket($refresh = false, $max = 0)
    {
        $token_cache_key = 'aquaz_wechat_js_ticket';
        $ticket = Cache::get($token_cache_key);
        if (empty($ticket) || $refresh) {
            $this->api_url = $this->uri_tickets."?type=jsapi&access_token=$this->access_token";
            $res = $this->curlCommon();
            if (empty($res->ticket) && $max < 3) {
                $max++;
                return $this->jsApiTicket(true, $max);
            }else{
                $ticket = $res->ticket;
                Cache::put($token_cache_key, $ticket, 110);
            }
        }
        return $ticket;
    }

}