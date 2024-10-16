将`_worker.js`代码托管到Cloudflare的Workers或Pages后，按照下面内容操作。

### 一、在Cloudflare中设置环境变量：

使用workers部署的，在`设置 >> 变量 >> 环境变量  >> 添加变量`中，添加下面5个变量：

| **变量名称**    | **说明**                                                     |
| --------------- | ------------------------------------------------------------ |
| UUID            | (可选) 可用为空，在代码中修改，比如：0648919d-8bf1-4d4c-8525-36cf487506ec |
| SOCKS5          | (可选) 可以为空，格式:  user:pass@host:port、:@host:port。它优选于PROXYIP |
| PROXYIP         | (可选) 可以为空，可以在代码中修改，格式：域名、IPv4、IPv4:PORT、[IPv6]、[IPv6]:PORT |
| CONFIG_PASSWORD | (可选) 查看节点配置的密码(这里指vless以及对应的clash.meta配置)，默认为空，无密码；使用：`http://your_worker_domain/config?pwd={CONFIG_PASSWORD}` |
| SUB_PASSWORD    | (可选) 查看节点订阅的密码，默认为空，无密码；使用：`https://your_worker_domain/sub?pwd={SUB_PASSWORD}&target={vless or clash}` |
| DOH_URL         | (可选) 填DNS over HTTPS（简称 DoH）的地址（它比DoT更加隐秘）。例如：https://1.1.1.1/dns-query、https://dns.google/dns-query |

使用Pages部署的，在`设置 >> 环境变量 >> 制作 >> 添加变量`中，添加前面的5个变量。

<img src="images\环境变量.png" />

注意：

1、Workers部署：添加、修改`环境变量`，立刻生效，如果没有生效，可能有延迟或浏览器缓存问题。

2、Pages部署：添加、修改`环境变量`，要重新部署Pages才生效。

3、不在CF中设置环境变量，而是在代码中修改，是可以的。

### 二、查看配置：

- 使用例子

```
https://a.abc.workers.dev/config?pwd=123456  # 假如123456是CF后台中，环境变量CONFIG_PASSWORD设置的值
```

### 三、查看订阅：

| 参数     | 含义                                                         |
| -------- | ------------------------------------------------------------ |
| pwd      | (必选/可选) 查看订阅的密码，CF后台中，设置了SUB_PASSWORD变量值，就要传入pwd={SUB_PASSWORD} |
| target   | (必选) target=vless 或 target=v2ray：v2ray订阅；target=clash：clash配置的订阅 |
| page     | (可选) 页码，默认为1，显示哪一页的vless或clash订阅内容？超出页码显示"Not found"，对传入cidr参数的值无效(更新订阅就能更换节点)。 |
| id       | (可选) 修改vless的uuid的值，仅用于修改订阅中UUID，不能使用新的UUID来连接这个脚本代理，几乎不用 |
| port     | (可选) 修改vless的port值                                     |
| hostName | (可选) 修改vless的sni和host的值，几乎不用                    |
| path     | (可选) 修改vless的path值，几乎不用                           |
| maxNode  | (可选) 修改每页最多写多少个节点，脚本会计算每页的节点数(平均数)，vless链接默认为1000，可选1-5000，clash默认为300，可选1-1000 |
| cidr     | (可选) 不使用脚本内，从`ipaddrURL`网页中，抓取的IP地址写入节点；使用地址传入的cidr生成的IP地址(随机1000个)写入节点。支持多个cidr（比如：cidr=104.30.1.0/24,108.162.255.0/24），只支持IPv4的CIDR。cidr随机生成的IP，最多1000个，不存在生成重复IP的情况。 |

#### 1、vless订阅，使用例子：

```
https://a.abc.workers.dev/sub?pwd=123456&target=vless                     # 第一页的vless节点
https://a.abc.workers.dev/sub?pwd=123456&target=vless&page=2              # 翻页，存在其它页，每页最多1000节点
https://a.abc.workers.dev/sub?pwd=123456&target=vless&id={uuid}           # 修改为其它uuid
https://a.abc.workers.dev/sub?pwd=123456&target=vless&port=2053           # 改为其它端口
https://a.abc.workers.dev/sub?pwd=123456&target=vless&hostName=githu.com  # 修改节点信息中的sni和host值
https://a.abc.workers.dev/sub?pwd=123456&target=vless&path=/hello         # 修改节点信息中的path
https://a.abc.workers.dev/sub?pwd=123456&target=vless&cidr=104.30.1.0/24
https://a.abc.workers.dev/sub?pwd=123456&target=vless&page=2&maxNode=200
https://a.abc.workers.dev/sub?pwd=123456&target=vless&page=2&maxNode=500&cidr=104.30.1.0/24,108.162.255.0/24
```

参数随意组合，只要参数是前面表格中的，都可以全部使用。

#### 2、Clash订阅，使用例子：

```
https://a.abc.workers.dev/sub?pwd=123456&target=clash                     # 第一页的clash配置
https://a.abc.workers.dev/sub?pwd=123456&target=clash&page=2              # 翻页，存在其它页，每页最多300节点
https://a.abc.workers.dev/sub?pwd=123456&target=clash&id={uuid}           # 修改为其它uuid
https://a.abc.workers.dev/sub?pwd=123456&target=clash&port=2053           # 改为其它端口
https://a.abc.workers.dev/sub?pwd=123456&target=clash&hostName=githu.com  # 修改节点信息中的sni和host值
https://a.abc.workers.dev/sub?pwd=123456&target=clash&path=/hello         # 修改节点信息中的path
https://a.abc.workers.dev/sub?pwd=123456&target=clash&cidr=104.30.1.0/24
https://a.abc.workers.dev/sub?pwd=123456&target=clash&page=2&maxNode=200
https://a.abc.workers.dev/sub?pwd=123456&target=clash&page=3&port=2053&cidr=104.30.1.0/24,108.162.255.0/24
```

参数随意组合，只要参数是前面表格中的，都可以全部使用。

### 四、（可选）巧用GitHub的私有仓库，隐藏您的反代IP、域名

如果您花费大量时间，收集一些反代IP、域名，被别人白嫖，而且您当前的网络环境抢不过别人，导致网速大不如以前，气不气？现在你不用为其烦恼，下面使用 GitHub 的私有仓库，将您收集的反代IP、域名的文件隐藏起来，只有对应的 token 才能访问，减少文件内容泄露的风险，保护您收集到的反代IP、域名。

##### 4.1 设置访问GitHub私有文件所需的参数（有两种方法）

- 第一种方法：在 Cloudflare Workers/Pages 中设置变量（推荐）


| 参数             | 含义                                                         |
| ---------------- | ------------------------------------------------------------ |
| GITHUB_TOKEN     | （必选）GitHub访问令牌，用于授权请求（获取方法，在后面）     |
| GITHUB_OWNER     | （必选）仓库所有者的用户名，填您的GitHub用户名               |
| GITHUB_REPO      | （必选）私有文件所在的仓库名称                               |
| GITHUB_BRANCH    | （可选）私有文件所在的分支名称，默认是main，如果您创建了其它分支，就改为您创建的分支名称 |
| GITHUB_FILE_PATH | （必选）私有文件所在的路径（是相对路径，不是绝对路径）       |

<img src="images\在cloudflare中设置与GitHub相关的变量(参数).png" />

- 第二种方法：在`_worker.js`源码中设置默认值（不推荐）

  与前面设置变量效果一样，名称不同而已，该方法可能会泄露您的 GitHub token。

<img src="images\在代码中设置与GitHub相关的参数.png" />

注意：代码所在的行数可能跟这里不同。

##### 4.2 GITHUB_TOKEN 值怎么获取？

1、获取 GitHub token 的地址：[link](https://github.com/settings/tokens)

2、获取 GitHub token 的教程

- 【官方版】创建 personal access token (classic) 的教程：[link](https://docs.github.com/zh/enterprise-server@3.10/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#%E5%88%9B%E5%BB%BA-personal-access-token-classic)
- 如何在 GitHub 生成经典的个人访问令牌(token)：[link](https://medium.com/@mbohlip/how-to-generate-a-classic-personal-access-token-in-github-04985b5432c7)

##### 4.3 优选的反代IP、域名文件的格式如下

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
注意：现在不支持在文件中添加对应的端口，也不支持csv文件。

### 五、（可选）通过path指定PROXYIP和SOCKS5

在v2rayN中，修改path的值，指定proxyip值和socks5的值（它们都支持ipv4、ipv4:port、[ipv6]、[ipv6]:port、domain.com、sub1.domain.com、sub2.sub1.domain.com、subN..sub1.domain.com格式）。

##### 1、PROXYIP的path

<img src="images\path设置proxyip.png" />

域名：

```
/proxyip=speed.cloudflare.com
```

IPv4地址：

```
/proxyip=192.168.1.1
/proxyip=192.168.1.1:443
```

IPv6地址：

```
/proxyip=[fe80::c789:ece7:5079:3406]
/proxyip=[fe80::c789:ece7:5079:3406]:443
```

注意：以上的PROXYIP，仅用于举例。

##### 2、SOCKS5的path

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

### 六、温馨提示

路径`src/worker.js`中的代码为开发中写的代码，大部代码根据[@zizifn](https://github.com/zizifn/edgetunnel/blob/main/src/worker-with-socks5-experimental.js)修改而来，如果不是开发者，使用`_wokers.js`的代码，简单修改一下UUID(前面提到的环境变量)，部署到cloudflare wokers或pages就可以使用。

### 七、免责声明

该项目仅供学习/研究目的，用户对法律合规和道德行为负责，作者对任何滥用行为概不负责。
