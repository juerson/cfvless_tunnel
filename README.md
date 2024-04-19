将`_worker.js`代码托管到Cloudflare的Workers或Pages后，按照下面内容操作。

### 一、在Cloudflare中设置环境变量：

使用workers部署的，在`设置 >> 变量 >> 环境变量  >> 添加变量`中，添加下面5个变量：

| **变量名称**    | **说明**                                                     |
| --------------- | ------------------------------------------------------------ |
| UUID            | 必须的，也可以在代码中添加，比如：0648919d-8bf1-4d4c-8525-36cf487506ec |
| SOCKS5          | 可以为空，格式：user:pass@host:port。它优选于PROXYIP         |
| PROXYIP         | 可以为空，或代码中修改，格式：域名或IP地址。比如：cdn.xn--b6gac.eu.org、cdn-all.xn--b6gac.eu.org、cdn-b100.xn--b6gac.eu.org等。 |
| CONFIG_PASSWORD | 查看节点配置的密码(这里指vless以及对应的clash.meta配置)，默认为空，无密码；使用：`http://your_worker_domain/config?pwd={CONFIG_PASSWORD}` |
| SUB_PASSWORD    | 查看节点订阅的密码，默认为空，无密码；使用：`https://your_worker_domain/sub?pwd={SUB_PASSWORD}&target={vless or clash}` |

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
| pwd      | (必须) 查看订阅的密码，密码是CF后台中环境变量SUB_PASSWORD设置的值 |
| target   | (必须) target=vless：vless链接的订阅；target=clash：clash配置的订阅 |
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

### 四、温馨提示

路径`src/worker.js`中的代码为开发中写的代码，大部代码根据[@zizifn](https://github.com/zizifn/edgetunnel/blob/main/src/worker-with-socks5-experimental.js)修改而来，如果不是开发者，使用`_wokers.js`的代码，简单修改一下UUID(前面提到的环境变量)，部署到cloudflare wokers或pages就可以使用。
