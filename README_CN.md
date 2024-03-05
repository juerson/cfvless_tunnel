## 一、Cloudflare Workers的部署方案：

- 1、直接将`_worker.js`中的代码复制到worker中；

- 2、添加UUID等环境变量，在部署的workers项目中，`设置 >> 变量 >> 环境变量 `中，添加4个变量（后面Pages部署，依然使用这个表格的变量）：

| **变量名称** | **值**                                                       |
| ------------ | ------------------------------------------------------------ |
| UUID         | 必须的，比如：5ed72ede-98bb-4dbf-aee3-34fd3a311efd           |
| SOCKS5       | 格式：user:pass@host:port。host:port格式的，网上找到这类socks5，添加到这里测试无效（不是socks5的地址和端口问题）；带身份认证的socks5能使用。SOCKS5和PROXYIP都设置了内容，不管SOCKS5是否能使用，都使用你设置的SOCKS5值，而忽略PROXYIP。SOCKS5变量的值为空或不存在，而PROXYIP值存在，才使用PROXYIP的值。 |
| PROXYIP      | 格式：域名或IP地址。这个变量跟SOCKS5，您可以二选一，通常使用PROXYIP。<br />其它网友共享的PROXYIP：cdn.xn--b6gac.eu.org、cdn-all.xn--b6gac.eu.org、cdn-b100.xn--b6gac.eu.org 等等。 |
| SHOW_VLESS   | 填on，访问"https://您的域名/UUID"，才能查看您部署的vless链接以及clash-meta信息。不存在该变量或将它设置为其它内容，是不能查看vless的分享链接和clash-meta配置信息的。 |

<img src="images\Snipaste_2024-03-05_16-30-35.png" title="Workers部署的，怎么添加UUID等环境变量？" style="zoom: 50%;" />

注意：Workers部署的方案，添加、修改`环境变量`，不需要重新部署，立刻生效（可能有延迟或浏览器有缓存，认为没有立刻生效，重新连接vless即可）；Pages部署的方案，添加、修改`环境变量`，要重新部署Pages才生效。

## 二、Cloudflare Pages的部署方案：

### 方法一：(连接GitHub存储库)

Fork代码到您的GitHub账号中 /下载这个代码库的所有代码重新上传到您的GitHub账号中，然后使用Cloudflare Pages连接您的Github存储库，然后设置`环境变量（高级）`（环境变量可以部署后再设置，但是添加、修改的环境变量必须`重新部署`才生效），保存并部署。

<img src="images\Snipaste_2024-03-05_15-21-05.png" title="部署前，添加环境变量" style="zoom: 50%;" />

部署Pages后，怎么添加、修改环境变量？

<img src="images\Snipaste_2024-03-05_17-12-16.png" title="部署Pages后，怎么添加、修改环境变量？" style="zoom: 50%;" />

注意：4个环境变量（cf vless老用户，知道vless的配置模板，只设置UUID、PROXYIP就够用了）

```txt
1、权限：SOCKS5 > PROXYIP

2、当SOCKS5不为空时，不管您设置的socks5代理能否使用，不会因socks5不能使用而自动跳到后面的PROXYIP而使用PROXYIP。

3、变量SOCKS5只能传入一个，不能传入多个；PROXYIP可以传入多个值，需要用英文逗号(,)隔开，不推荐设置多个值，本来IP地址就不是固定的，你设置的PROXYIP也在变，增加国外账号被封的风险，要换PROXYIP，在环境变量中修改，或添加自己的域名，修改域名指向的IP地址，比在源码中修改(有时无法保存修改的内容)，方便了很多。

4、自己没有Socks5账号，就不用设置SOCKS5变量，把SOCKS5变量删除/不设置它，不影响脚本运行。

5、只设置UUID变量，其它3个变量不设置，就能使用(cf vless老用户知道配置信息，修改部分信息即可)，就是部分网站无法访问的（如果需要，就要设置PROXYIP或SOCKS5）。

6、变量SHOW_VLESS主要是开启和关闭查看您的vless分享链接的网页，on则显示vless的分享链接和clash-meta的配置信息，其它字符串或"没有设置这个变量"一律不让查看vless分享链接。刚部署时，不知道vless怎么配置，把SHOW_VLESS设置为on，就能查看，提取配置信息或vless链接后，把SHOW_VLESS改为其它值，就不能查看vless链接。

7、Cloudflare Pages部署的，需要重新部署，环境变量才生效。
```

下面重新部署Pages，让修改的环境变量生效：

<img src="images\Snipaste_2024-03-05_17-24-58.png" title="重新部署Pages，让修改的环境变量生效" style="zoom: 50%;" />

### 方法二：(本地电脑上传)

先上传源码到`Cloudflare Pages`中，部署后，添加4个环境变量（uuid是必须的）：

<img src="images\Snipaste_2024-03-05_18-07-42.png" style="zoom: 50%;" />

上传代码的，怎么让新设置的环境变量生效？

<img src="images\Snipaste_2024-03-05_18-18-32.png" title="上传代码的，怎么让新设置的环境变量生效？" style="zoom: 50%;" />

##### _worker.js代码根据[@zizifn](https://github.com/zizifn/edgetunnel/blob/main/src/worker-with-socks5-experimental.js)小幅度修改。
