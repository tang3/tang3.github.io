0x00 Meta
---------

所有的文章都为 `markdown` 格式,且文章标题格式必须是 `2016-01-01-your_title.md`, 同时必须
以如下代码片段开头：

```
---
layout: post
title: 文章标题
author: 作者名
author_url: http:example.com  (作者的微博,主页等联系网址,可选.)
categories: [category_1, category_2, ...]  (从"漏洞分析,技术分享,web安全,二进制安全"中选择一二。)
tags: [tag1, tag2, tag3] (酌情添加即可)
---

文章正文内容
```

0x01  图片&链接
--------------

![webshell]({{ site.baseurl }}/assets/images/2016-04/demo.jpg)

所有的图片资源主目录为 `/assets/images/`, 如果有其他类型的资源文件，如 zip, pdf, .tar.gz 等其
他格式文件，将使用 `/assets/downloads/` 目录。所以建议文章提交者使用如下目录格式:

```
2016-01-10-your_title/
    2016-01-10-your_title.md   # 你的文章 markdown 文件。
    images/                    # 此目录中的文件将按年月归于 /assets/images 中
        2016-01/
            python.jpg
            ruby.png
    downloads/                 # 此目录中的文件将将按年月归于 /assets/downloads 中
        2016-01/
            poc.zip
            source.tar.gz


```

{% raw %}
然后在文章中,就可以使用如下的格式引用,注意加上`{{ site.baseurl }}`如:


```
引用图片:
![python]({{ site.baseurl }}/assets/images/2016-01/python.jpg)

引用其他格式文件:
[点击下载 poc.zip]({{ site.baseurl }}/assets/downloads/2016-01/poc.zip)
```
{% endraw %}

0x02 代码高亮
------------

代码块必须指定相应的编程语言才可以高亮.

````
```c {python, ruby, java, php ...}
void set_cred(struct cred *kcred)
{
    struct cred cred_buf;
    int len;

    len = read_pipe(kcred, &cred_buf, sizeof(cred_buf));
    cred_buf.uid = cred_buf.euid = cred_buf.suid = cred_buf.fsuid = 0;
    cred_buf.gid = cred_buf.egid = cred_buf.sgid = cred_buf.fsgid = 0;
    len = write_pipe(kcred, &cred_buf, sizeof(cred_buf));
}
```
````
