<?php
return [
    'debug'         => env('wx_debug'),           // 调试模式
    'app_id'        => env('wx_app_id'),          // 应用id
    'app_secret'    => env('wx_app_secret'),      // 应用密钥
    'mch_id'        => env('wx_mch_id'),          // 商户ID
    'mch_key'       => env('wx_mch_key'),         // 商户密钥
    'notify_url'    => env('wx_notify_url'),      // 支付通知地址
];