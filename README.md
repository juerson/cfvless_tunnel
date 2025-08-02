将`_worker.js`（订阅版）或`_worker_基础版.js`代码托管到Cloudflare的Workers或Pages后，按照下面内容操作。

## 一、CF中，设置环境变量

| **变量名称**    | **说明**                                                     |
| --------------- | ------------------------------------------------------------ |
| UUID4           | (必选) 用于Vless协议的userID，例如：61098bdc-b734-4874-9e87-d18b1ef1cfaf |
| USERPWD         | (可选) 用于Trojan协议的password，在环境变量中设置，没有设置就是采用上面设置那个UUID4 |
| ENABLED_S5      | (可选) 用于开启Shadowsocks协议，默认是关闭，不能使用它，慎用，由于无密码认证，域名一旦泄露，别人会盗用你的CF Workers使用量，启用它的有效值范围：['1', 'true', 'yes', 'on'] |
| LANDING_ADDRESS | (可选) 等价于大家公认的PROXYIP，改一个名字而已，不设置它，一些网站无法打开，格式：(Sub-)Domain:PORT、IPv4:PORT、[IPv6]:PORT（没有端口，默认是443端口） |
| SOCKS5          | (可选) 不设置，一些网站无法打开，格式:  user:pass@host:port、:@host:port。它优先于LANDING_ADDRESS和NAT64，节点path中设置的`/pyip`或`/socks`为最高优先级 |
| NAT64           | (可选) 兜底的PROXYIP替换方法，代码中设置的那个无效了，刚部署的，不能访问CF和CF保护的CDN站点（chatgpt、Netflix等这些站点） |
| CONFIG_PASSWORD | (可选) 订阅版专用，用于查看v2ray、singbox、clash的配置例子，使用示例：`http://your_worker_domain/config?pwd={CONFIG_PASSWORD}` |
| SUB_PASSWORD    | (可选) 订阅版专用，用于查看订阅内容或导入对应的客户端使用（支持v2ray、singbox、clash三种订阅方式）。使用示例：`https://your_worker_domain/sub?pwd={SUB_PASSWORD}&target={v2ray, singbox, clash}`，注意：订阅中所用到的DATA_SOURCE_URL数据要修改成自己的，要不然订阅的内容一直都不变的，也可能不能使用。 |
| GITHUB_TOKEN     | (非必须) 订阅版专用，Github token                                 |
| GITHUB_OWNER     | (非必须) 订阅版专用，仓库拥有者                                    |
| GITHUB_REPO      | (非必须) 订阅版专用，仓库名                                        |
| GITHUB_BRANCH    | (非必须) 订阅版专用，分支名(通常是main/master)                     |
| GITHUB_FILE_PATH | (非必须) 订阅版专用，文件路径(相对于仓库根目录)                    |
| DATA_SOURCE_URL | (非必须) 订阅版专用，用于更改数据源URL，它指的是优选IP和域名的txt文件，无端口且每行一个，格式为 "https\://example.com/data.txt"，当GitHub的所有变量参数都没有设置或无效，包括没有读取到数据时，它才有效。 |

### 1、部署基础版的代码，能设置的环境变量：

<img src="images\基础参数设置.png" />

### 2、部署订阅版的代码，能设置的环境变量，除了前面哪些变量外，还能设置：

非必要设置，不设置，节点有被别人查看和使用的风险，特别是`/sub?pwd=`、`/config?pwd=`没有设置密码，还部署了订阅版的代码。

<img src="images\订阅版需添加的参数.png" />

注意：使用Pages方法部署的，添加、修改`环境变量`，要重新部署Pages才生效。

## 二、订阅版

### 1、v2ray分享链接、singbox和clash配置怎么样的？

- 使用例子

```
https://worker.username.workers.dev/config?pwd=123456  # 假如123456是CF后台中，环境变量CONFIG_PASSWORD设置的值
```

### 2、怎么使用订阅

| 参数   | 含义                                                         |
| ------ | ------------------------------------------------------------ |
| pwd    | (必选/可选) 查看订阅的密码，CF后台中，设置了SUB_PASSWORD变量值，就要传入pwd={SUB_PASSWORD} |
| target | (必选) target=v2ray、singbox、clash，分别是v2ray分享链接的订阅、singbox的订阅、clash的订阅 |
| page   | (可选) 页码，默认为1，如果DATA_SOURCE_URL/GitHub私有文件的静态文件，数据多，使用哪一页的数据订阅内容？ |
| port   | (可选) 不采用随机端口（随机内置的几个端口的其中一个），而采用固定的端口值，写入订阅里节点的port中 |
| path   | (可选) 修改节点的path值，不是更换打开订阅的路径，而是修改节点配置里面的path |
| host   | (可选) 修改节点sni和host的值，仅用于修改订阅中sni和host值，不能使用它连接这个脚本进行代理 |
| max    | (可选) 修改每页最多写多少个节点。v2ray链接默认为300，可选1-2000；clash默认为30，可选1-100；singbox默认为30，可选1~100。 |
| cidr   | (可选) 不使用从DATA_SOURCE_URL/GitHub私有文件获取的数据写入节点，而是使用从url传入的cidr参数值生成的唯一不重复IP地址写入节点。注意：只支持IPv4的CIDR。 |

#### （1）v2ray订阅，使用例子：

```
https://worker.username.workers.dev/sub?pwd=123456&target=v2ray                     # 第一页的节点
https://worker.username.workers.dev/sub?pwd=123456&target=v2ray&page=2              # 翻页，第二页
https://worker.username.workers.dev/sub?pwd=123456&target=v2ray&port=2053           # 全部都使用这个端口
https://worker.username.workers.dev/sub?pwd=123456&target=v2ray&host=githu.com      # 修改节点信息中的sni和host值
https://worker.username.workers.dev/sub?pwd=123456&target=v2ray&path=/?ed=2560      # 修改节点信息中的path
https://worker.username.workers.dev/sub?pwd=123456&target=v2ray&cidr=104.16.0.0/13  # 使用这个cidr范围内的随机IP生成订阅
```

#### （2）SingBox订阅，使用例子：

```
https://worker.username.workers.dev/sub?pwd=123456&target=singbox                     # 第一页的节点
https://worker.username.workers.dev/sub?pwd=123456&target=singbox&page=2              # 翻页，第二页
https://worker.username.workers.dev/sub?pwd=123456&target=singbox&port=2053           # 全部都使用这个端口
https://worker.username.workers.dev/sub?pwd=123456&target=singbox&host=githu.com      # 修改节点信息中的sni和host值
https://worker.username.workers.dev/sub?pwd=123456&target=singbox&path=/?ed=2560      # 修改节点信息中的path
https://worker.username.workers.dev/sub?pwd=123456&target=singbox&cidr=104.16.0.0/13  # 使用这个cidr范围内的随机IP生成订阅
```

#### （3）Clash订阅，使用例子：

```
https://worker.username.workers.dev/sub?pwd=123456&target=clash                     # 第一页的节点
https://worker.username.workers.dev/sub?pwd=123456&target=clash&page=2              # 翻页，第二页
https://worker.username.workers.dev/sub?pwd=123456&target=clash&port=2053           # 全部都使用这个端口
https://worker.username.workers.dev/sub?pwd=123456&target=clash&host=githu.com      # 修改节点信息中的sni和host值
https://worker.username.workers.dev/sub?pwd=123456&target=clash&path=/?ed=2560      # 修改节点信息中的path
https://worker.username.workers.dev/sub?pwd=123456&target=clash&cidr=104.16.0.0/13  # 使用这个cidr范围内的随机IP生成订阅
```

注意：

1、前面那些参数可以随意组合，只要参数是前面表格中的，都可以全部使用。

2、由于订阅DATA_SOURCE_URL链接的数据不是时刻维护/无私奉献分享给您，里面的地址可能不能使用，或者能使用，但是网速差的情况，就需要自己更新它，有需要的更改为自己的，或者使用下面的GitHub私有仓库解决。

### 3、巧用GitHub的私有仓库，隐藏您搜集的反代IP和域名

如果您花费大量时间，收集一些反代IP、域名，被别人白嫖，而且您当前的网络环境抢不过别人，导致网速大不如以前，气不气？现在你不用为其烦恼，下面使用 GitHub 的私有仓库，将您收集的反代IP、域名的文件隐藏起来，只有对应的 token 才能访问，减少文件内容泄露的风险，保护您收集到的反代IP、域名。

#### （1）设置访问GitHub私有文件所需的参数


| 参数             | 含义                                                         |
| ---------------- | ------------------------------------------------------------ |
| GITHUB_TOKEN     | （必选）GitHub访问令牌，用于授权请求（获取方法，在后面）     |
| GITHUB_OWNER     | （必选）仓库所有者的用户名，填您的GitHub用户名               |
| GITHUB_REPO      | （必选）私有文件所在的仓库名称                               |
| GITHUB_BRANCH    | （可选）私有文件所在的分支名称，默认是main，如果您创建了其它分支，就改为您创建的分支名称 |
| GITHUB_FILE_PATH | （必选）私有文件所在的路径（是相对路径，不是绝对路径）       |

<img src="images\在cloudflare中设置与GitHub相关的变量(参数).png" style="zoom:50%;" />

#### （2）GITHUB_TOKEN 值怎么获取？

1、获取 GitHub token 的地址：[link](https://github.com/settings/tokens)

2、获取 GitHub token 的教程

- 【官方版】创建 personal access token (classic) 的教程：[link](https://docs.github.com/zh/enterprise-server@3.10/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#%E5%88%9B%E5%BB%BA-personal-access-token-classic)
- 如何在 GitHub 生成经典的个人访问令牌(token)：[link](https://medium.com/@mbohlip/how-to-generate-a-classic-personal-access-token-in-github-04985b5432c7)

#### （3）优选的CF IP、反代IP和域名

```txt
time.cloudflare.com
time.is
ip.sb
172.64.229.197
104.19.106.250
104.19.124.30
104.19.206.63
104.18.200.122
104.19.113.92
172.64.203.72
172.64.53.56
```
注意：不支持在文件中添加对应的端口，也不支持csv文件。

## 三、通过path指定LANDING_ADDRESS和SOCKS5

在v2rayN中，单独修改path的值，指定landingAddress值和socks5的值；也可以在singbox、clash订阅中，修改对应节点path键的值。

**支持格式：**ipv4、ipv4:port、[ipv6]、[ipv6]:port、domain.com、sub1.domain.com、sub2.sub1.domain.com、subN..sub1.domain.com

**注意：**没有端口，默认使用443端口，其它端口需要写出来；LANDING_ADDRESS指大家公认的PROXYIP。

### 1、LANDING_ADDRESS的path

<img src="images\path设置proxyip.png" />

域名：

```
/pyip=speed.cloudflare.com
/pyip=speed.cloudflare.com:443
```

IPv4地址：

```
/pyip=192.168.1.1
/pyip=192.168.1.1:443
```

IPv6地址：

```
/pyip=[fe80::c789:ece7:5079:3406]
/pyip=[fe80::c789:ece7:5079:3406]:443
```

注意：以上的LANDING_ADDRESS，仅用于举例。

### 2、SOCKS5的path

<img src="images\path设置socks5.png" />

用户密码认证的socks5：

```
/socks=user:pass@72.167.46.208:1080
```

匿名方式的socks5（无需用户名和密码）：

```
/socks=72.167.46.208:1080
```

注意：以上的socks5，仅用于举例，还有socks5的密码含有一些特殊字符的，可能在这里设置没有用。

## 四、温馨提示

1、关于订阅版和基础版部署代码，要清楚自己部署那个代码。

```
     源码              可直接部署到cloudflare的部署代码
src/worker.js -----------|=> dist/worker.js
						 |=> _worker.js

src/worker-基础版.js -----|=> dist/worker-基础版.js
                         |=> _worker-基础版.js
```

2、路径`src/`下所有代码为开发中写的源代码，大部代码根据[@zizifn](https://github.com/zizifn/edgetunnel)、[@ca110us](https://github.com/ca110us/epeius)、[@FoolVPN-ID](https://github.com/FoolVPN-ID/Nautica)修改而来，如果不是开发者，使用 `_wokers.js` 或`_worker_基础版.js`的代码，简单修改一下前面提到的环境变量，部署到cloudflare wokers或pages就可以使用。

3、部署时，有几率遇到Error 1101错误，建议将原js代码进行混淆，如果js混淆后，依然无法解决问题，就等开发者遇到该问题且有时间再解决这个问题。

<img src="images\Error 1101.png" style="zoom:50%;" />

4、shadowsocks协议的，如果启用使用，可以手动安照下面配置，只靠tls加密保护上网数据

<img src="images\ss.png" style="zoom: 67%;" />

## 五、免责声明

该项目仅供学习/研究目的，用户对法律合规和道德行为负责，作者对任何滥用行为概不负责。
