// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:05 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = '0648919d-8bf1-4d4c-8525-36cf487506ec'; // 备用UUID

let proxyList = ['cdn-all.xn--b6gac.eu.org', 'cdn.xn--b6gac.eu.org', 'cdn-b100.xn--b6gac.eu.org', 'edgetunnel.anycast.eu.org', 'cdn.anycast.eu.org'];
let proxyIP = proxyList[Math.floor(Math.random() * proxyList.length)]; // 备用代理IP地址

// The user name and password do not contain special characters
// Setting the address will ignore proxyIP
// Example:  user:pass@host:port  or  host:port
let socks5Address = ""; // 备用socks5代理地址，socks5Address优先于proxyIP

let ipaddrURL = "https://ipupdate.baipiao.eu.org/"; // 网友收集的CDN地址


/**
 * 三种方法，获取clash配置模板：
 * 1、使用网友搭建的节点转换网址，传入一个虚假节点(ss://MjAyMi1ibGFrZTMtY2hhY2hhMjAtcG9seTEzMDU6MTIzNDU2Nzg=@127.0.0.1:443#001),生成clash配置文件，把它爬取下来
 * 2、使用GitHub中的gist(https://gist.github.com，注意：修改后，要更新url链接),把模板存到这里，worker脚本抓取这个链接，把配置文本爬取下来
 * 3、使用cloudflare workers KV存储，把模板存到KV里面，worker脚本从KV里面读取模板文本
 * 推荐使用第3种方法，因为它可以随时更新模板，而且不需要更新worker脚本。本worker脚本优选使用它（后面的代码中kv_ipaddr和kv_clash_template都是使用KV中的密钥值）。
 */

/*
	节点转换网址：(别人的订阅转换地址，随时会失效，重复的节点转换会被节点转换网站检查到，随时会如入黑名单，无法长时间使用)
							大概流程是传入一个虚假的节点链接过去，返回clash配置模板，
							比如：ss://MjAyMi1ibGFrZTMtY2hhY2hhMjAtcG9seTEzMDU6MTIzNDU2Nzg=@127.0.0.1:443#001
*/
// let nodeConverterURL = "https://api.subcloud.xyz/sub?target=clash&url=ss%3A%2F%2FMjAyMi1ibGFrZTMtY2hhY2hhMjAtcG9seTEzMDU6MTIzNDU2Nzg%3D%40127.0.0.1%3A443%23001&insert=false&config=https%3A%2F%2Fraw.githubusercontent.com%2FACL4SSR%2FACL4SSR%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online.ini&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true";
// let nodeConverterURL = "https://subapi.imgki.com/sub?target=clash&url=ss%3A%2F%2FMjAyMi1ibGFrZTMtY2hhY2hhMjAtcG9seTEzMDU6MTIzNDU2Nzg%3D%40127.0.0.1%3A443%23001&insert=false";

let clash_template_url = "https://raw.githubusercontent.com/juerson/cfvless_tunnel/master/clash_template.yaml";

// 查看配置信息和订阅文件的密码
let configPassword = ""; // 备用密码(优先使用环境变量)，查询vless配置信息的密码，http://your_worker_domain/config?pwd={CONFIG_PASSWORD}
let subPassword = ""; // 备用密码(优先使用环境变量)，订阅地址的密码，显示订阅地址的节点和clash-meta配置信息，https://your_worker_domain/sub?pwd={SUBSCRIPTIONS_PASSWORD}&target={vless or clash}

const domainList = [
	'https://www.iq.com',
	'https://www.dell.com',
	'https://www.bilibili.com',
	'https://www.alibaba.com',
	'https://fmovies.llc/home',
	'https://www.visaitalia.com/',
	'https://www.techspot.com'
];

let parsedSocks5Address = {};
let enableSocks = false;

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, SOCKS5: string, CONFIG_PASSWORD: string, SUBSCRIPTIONS_PASSWORD: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			/** 先检查cf中的环境变量存在就使用它，不存在就使用"||"右边的 */
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;
			socks5Address = env.SOCKS5 || socks5Address; // socks5代理优先于proxyIP
			// 获取vless配置信息的密码。前端使用访问： https://{your_worker_domain}/config?pwd={CONFIG_PASSWORD}
			configPassword = env.CONFIG_PASSWORD || configPassword;
			// 订阅地址的密码。前端使用访问：https://{your_worker_domain}/sub?pwd={SUBSCRIPTIONS_PASSWORD}&target={vless or clash}
			// 可选参数（一个或多个），顺序不固定：&page=1&id={your_vless_uuid}&port={port}&cidr={cidr}&path={your_vless_path}&hostName={your_worker_domain}
			subPassword = env.SUBSCRIPTIONS_PASSWORD || subPassword;

			/* 读取/获取KV命令空间里面的密钥值（IP地址和clash配置模板） */
			let kv_ipaddr = await env.CLASH_WITH_ADDRESS.get("ipaddr"); // ipaddr来源于KV命名空间里面的密钥
			let kv_clash_template = await env.CLASH_WITH_ADDRESS.get("config_template"); // 同理，config_template来源于KV命名空间里面的密钥

			// 检查字符串中是否有逗号
			if (proxyIP.includes(',')) {
				// 如果有逗号，将字符串分割成数组
				const arr = proxyIP.split(',');
				// 生成一个随机索引
				const randomIndex = Math.floor(Math.random() * arr.length);
				// 选取随机索引对应的元素赋值给同一个变量
				proxyIP = arr[randomIndex].trim();
			} else {
				// 如果没有逗号，直接使用原始字符串
				proxyIP = proxyIP.trim();
			}
			if (socks5Address) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Address);
					enableSocks = true;
				} catch (err) {
					/** @type {Error} */
					let e = err;
					console.log(e.toString());
					enableSocks = false;
				}
			}
			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case '/':
						const randomDomain = domainList[Math.floor(Math.random() * domainList.length)];
						const redirectResponse = new Response('', {
							status: 301,
							headers: {
								'Location': randomDomain
							}
						});
						return redirectResponse;
					case `/config`: {
						const url = new URL(request.url);
						let password = url.searchParams.get('pwd') || ""; 			// 接收pwd参数密码，必须的（密码不匹配，则不能查vless节点和clash-meta的配置信息）
						if (password) { 																				// 防止XSS攻击（恶意注入代码破解）
							password = encodeURIComponent(password); 							// 将get请求接收的pwd参数(密码)进行编码
							configPassword = encodeURIComponent(configPassword); 	// 将配置文件查询的密码编码
						}
						// 密码正确，才显示vless配置信息
						if (configPassword === password) {
							const vlessConfig = getVLESSConfig(userID, request.headers.get('Host'));
							return new Response(`${vlessConfig}`, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						} else {
							return new Response('Not found', { status: 404 });
						}
					}
					case `/sub`:
						const url = new URL(request.url);
						let password = url.searchParams.get('pwd') || "";	// 接收pwd参数(password的简写，密码)，不传入pwd参数则不能查看订阅地址的节点和clash-meta配置信息
						let target = url.searchParams.get('target');			// 接收target参数，指向什么订阅？vless or clash?，必须的
						let hostName = url.searchParams.get('hostName') || url.hostname;	// 接收hostName参数，没有则使用当前网页的域名，可选的（填充到vless中的sni和host）
						userID = url.searchParams.get('id') || userID; 	  // 接收id参数，没有则使用默认值，可选的
						let portParam = url.searchParams.get('port');   	// 接收port参数，可选的
						let pathParam = url.searchParams.get('path');	    // 接收path参数，可选的
						let cidrParam = url.searchParams.get('cidr');	    // 就收cidr参数，可选的，如：cidr=104.21.192.0/19,104.21.64.0/19

						if (password) { // 防止XSS攻击（恶意注入代码破解），使用encodeURIComponent()
							password = encodeURIComponent(password); 			 // 将get请求接收的pwd参数(密码)进行编码
							subPassword = encodeURIComponent(subPassword); // 将订阅密码编码
						}

						// 检查传入的id参数是否为合法的uuid
						if (!isValidUUID(userID)) {
							throw new Error('uuid is not valid');
						}

						let port = portParam || 443;
						let path = pathParam ? encodeURIComponent(pathParam) : "%2F%3Fed%3D2048"; // 对path进行url编码，没有path参数则使用默认值
						let ipsArray = []; // 后面vless、clash中要使用到
						/**
						 * 这个if...else if...判断条件，为了获取IP地址，添加到ipsArray，有2种情况：
						 * 		1. 传入了cidr参数，则从cidr参数中的cidr中生成IP地址
						 * 		2. 使用内置ipaddrURL地址，抓取网页中的纯IPv4地址，或KV中ipaddr密钥值中的IP地址
						 * 顺便对IP地址排序，翻页时，保证IP地址的顺序（CIDR，随机生成的，顺序会被打乱）
						 */
						if (!cidrParam && password === subPassword) {
							/**
							 * Cloudflare workers KV中的ipaddr密钥值存在，就使用它，否则使用ipaddrURL网页的IP地址
							 */
							let ips_string = "";
							if (kv_ipaddr) {
								ips_string = kv_ipaddr;
							} else {
								ips_string = await fetchWebPageContent(ipaddrURL); // 抓取网页的内容
							}
							let ips_Array = ips_string.trim().split(/\r\n|\n|\r/).map(ip => ip.trim()); // 分割出ip地址到数组中
							console.log(ips_Array);
							// Array.prototype.push.apply(vlessArray, ips_Array); 		   // 将ips_Array中的所有元素添加到vlessArray中
							ipsArray = sortIpAddresses(ips_Array); 								 			 // 按照IP地址排序（可以排序非IP地址），便于后面分页显示
						} else if (cidrParam && password === subPassword) { 		 			 // 使用地址传入的cidr参数生成vless链接
							let ips_Array = getCidrParamAndGenerateIps(cidrParam); 			 // 截取get请求中的cidr参数并生成ip数组(最多1000个)
							ipsArray = sortIpAddresses(ips_Array); 							   			 // 按照IP地址排序（可以排序非IP地址），便于后面分页显示
						} else {
							return new Response('Not found', { status: 404 }); 		 			 // 通常是密码错误的情况才显示Not found
						}
						if (target === "vless") {
							/**
							 * 分页创建vless节点：防止太多节点，全部生成到一个vless配置文件，导致浏览器、v2rayN等客户端卡死
							 *
							 * Page参数：页码，必须是整数，默认为1，从1开始，超出页码范围(由程序动态计算)则显示Not found，每页可以单独使用
							 * maxNode参数：每页最多的节点数，默认1000个
							 * 
							 * 注意：
							 * 		1、翻页CIDR，可能会导致节点重复，因为每次翻页都会生成新的IP地址；CIDR范围内的IP数小于maxNodeNumber数，会导致不满maxNodeNumber，节点不会重复
							 * 		2、翻页ipaddrURL抓取的内容或KV中ipaddr地址，在远程服务器没有更新内容情况下，生成的节点不会重复
							 */
							let page = url.searchParams.get("page") || 1; 							 // 从1开始的页码
							let maxNodeNumber = url.searchParams.get('maxNode') || 1000; // 获取get请求链接中的maxNode参数(最大节点数)
							maxNodeNumber = (maxNodeNumber > 0 && maxNodeNumber <= 5000) ? maxNodeNumber : 1000; // 限制最大节点数
							// splitArrayEvenly函数：ipArray数组分割成每个子数组都不超过maxNode的数组(子数组之间元素个数平均分配)
							let chunkedArray = splitArrayEvenly(ipsArray, maxNodeNumber);
							let totalPage = Math.ceil(ipsArray.length / maxNodeNumber);  // 计算总页数
							// 剔除不合法的，页码超出范围，返回404
							if (page > totalPage || page < 1) {
								return new Response('Not found', { status: 404 });
							}
							let ipsArrayChunked = chunkedArray[page - 1]; // 使用哪个子数组的数据？ “page - 1”：保证索引是从0开始的，前面设置页码从1开始了
							let reusltArray = eachIpsArrayAndGenerateVless(ipsArrayChunked, hostName, port, path, userID); // 遍历ipsArray生成vless链接
							let vlessArrayStr = reusltArray.join('\n');   // 将数组转换为字符串(换行)
							// let encoded = btoa(vlessArrayStr); // base64编码
							return new Response(vlessArrayStr, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
						} else if (target === "clash") {
							/**
							 * 分页创建clash配置文件：防止大量数据，全部生成到一个clash配置文件，导入clash客户端使用，软件卡死。
							 * 
							 * Page参数：页码，必须是整数，默认从1开始，超出页码范围(由程序动态计算)则显示Not found，每页可以单独使用
							 * maxNode参数：每页最多的节点数，默认300个
							 * 
							 * 注意：
							 * 		1、翻页CIDR，可能会导致节点重复，因为每次翻页都会生成新的IP地址；CIDR范围内的IP数小于maxNodeNumber数，会导致不满maxNodeNumber，节点不会重复
							 * 		2、翻页ipaddrURL抓取的内容或KV中ipaddr地址，在远程服务器没有更新内容情况下，生成的节点不会重复
							 */
							let page = url.searchParams.get("page") || 1; 						  // 从1开始的页码
							let maxNode = url.searchParams.get('maxNode') || 300; 			// 获取get请求链接中的maxNode参数(最大节点数)
							maxNode = (maxNode > 0 && maxNode <= 1000) ? maxNode : 300; // 限制最大节点数
							// splitArrayEvenly函数：ipArray数组分割成每个子数组都不超过maxNode的数组(子数组之间元素个数平均分配)
							let chunkedArray = splitArrayEvenly(ipsArray, maxNode);
							let totalPage = Math.ceil(ipsArray.length / maxNode); 			// 计算总页数
							// 剔除不合法的，页码超出范围，返回404
							if (page > totalPage || page < 1) {
								return new Response('Not found', { status: 404 });
							}
							/**
							 * Cloudflare workers KV中的clash_template密钥值存在就使用它，否则使用clash_template_url提供的clash配置文件模板
							 */
							let clash_template = "";
							if (kv_clash_template) {
								clash_template = kv_clash_template; // 这里使用KV内的clash配置模板
							} else {
								clash_template = await fetchWebPageContent(clash_template_url); // 这里抓取网页的clash配置内容(clash配置模板)
							}
							let ipsArrayChunked = chunkedArray[page - 1]; // 使用哪个子数组的数据？ “page - 1”：保证索引是从0开始的，前面设置页码从1开始了
							let proxyies = [];
							let nodeNameArray = [];
							for (let i = 0; i < ipsArrayChunked.length; i++) {
								let ipaddr = ipsArrayChunked[i];		// 获取IP地址、server
								let nodeName = `${ipaddr}:${port}`; // 节点名称
								let tls = (hostName.includes("workers.dev")) ? false : true; // 是否开启tls
								let sni = tls ? hostName : ""; 			// tls为true则使用hostName，否则为空
								let clashConfig = `  - {"type":"vless","name":"${nodeName}","server":"${ipaddr}","port":${port},"uuid":"${userID}","network":"ws","tls":${tls},"udp":false,"sni":"${sni}","client-fingerprint":"chrome","ws-opts":{"path":"${path}","headers":{"host":"${hostName}"}}}`;
								proxyies.push(clashConfig);				  // 节点的配置信息
								nodeNameArray.push(nodeName); 		  // 节点名称，在clash分组中使用
							}
							// 替换clash配置中proxies字段的节点(ss节点数据)，要替换的内容一定要一模一样
							let replaceProxyies = clash_template.replace(/  - {name: 01, server: 127.0.0.1, port: 80, type: ss, cipher: aes-128-gcm, password: a123456}/g, proxyies.join('\n'));
							// 替换proxy-groups中的proxies节点名称，生成最终的clash的配置文件信息
							let clashConfig = replaceProxyies.replace(/      - 01/g, nodeNameArray.map(ipWithPort => `      - ${ipWithPort}`).join("\n")).replace(/dns-failed,/g, ""); // 如果一些节点转换为clash存在“dns-failed,”字符串，就要删除掉，否则导入clash程序使用会报错
							return new Response(clashConfig, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
						}
					default:
						return new Response('Not found', { status: 404 });
				}
			} else {
				return await vlessOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

/**
 * 
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function vlessOverWSHandler(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				addressType,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processVlessHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '
				} `;
			if (hasError) {
				// controller.error(message);
				throw new Error(message); // cf seems has bug, controller.error will not end stream
				// webSocket.close(1000, message);
				return;
			}
			// if UDP but port not DNS port, close it
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					// controller.error('UDP proxy only enable for DNS which is port 53');
					throw new Error('UDP proxy only enable for DNS which is port 53'); // cf seems has bug, controller.error will not end stream
					return;
				}
			}
			// ["version", "附加信息长度 N"]
			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, vlessResponseHeader, log);
			}
			handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {number} addressType The remote address type to connect to.
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {
	async function connectAndWrite(address, port, socks = false) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
			: connect({
				hostname: address,
				port: port,
			});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); // first write, normal is tls client hello
		writer.releaseLock();
		return tcpSocket;
	}

	// if the cf connect tcp socket have no incoming data, we retry to redirect ip
	async function retry() {
		if (enableSocks) {
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		}
		// no matter retry success or not, close websocket
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	let tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// when remoteSocket is ready, pass to websocket
	// remote--> ws
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader for ws 0rtt
 * @param {(info: string)=> void} log for ws 0rtt
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});

			// The event means that the client closed the client -> server stream.
			// However, the server -> client stream is still open until you call close() on the server side.
			// The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
			webSocketServer.addEventListener('close', () => {
				// client send close, need close server
				// if stream is cancel, skip controller.close
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			}
			);
			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			}
			);
			// for ws 0rtt
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
			// if ws can stop read if stream is full, we can implement backpressure
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},
		cancel(reason) {
			// 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
			// 2. if readableStream is cancel, all controller.close/enqueue need skip,
			// 3. but from testing controller.error still work even if readableStream is cancel
			if (readableStreamCancel) {
				return;
			}
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;

}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * 
 * @param { ArrayBuffer} vlessBuffer 
 * @param {string} userID 
 * @returns 
 */
function processVlessHeader(
	vlessBuffer,
	userID
) {
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}
	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID) {
		isValidUser = true;
	}
	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	//skip opt for now

	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1--> ipv4  addressLength =4
	// 2--> domain name addressLength=addressBuffer[1]
	// 3--> ipv6  addressLength =16
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP,
	};
}

/**
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} vlessResponseHeader 
 * @param {(() => Promise<void>) | null} retry
 * @param {*} log 
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	// remote--> ws
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false; // check if remoteSocket has incoming data
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				/**
				 * 
				 * @param {Uint8Array} chunk 
				 * @param {*} controller 
				 */
				async write(chunk, controller) {
					hasIncomingData = true;
					// remoteChunkCount++;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						// seems no need rate limit this, CF seems fix this??..
						// if (remoteChunkCount > 20000) {
						// 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
						// 	await delay(1);
						// }
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
					// safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	// seems is cf connect socket have error,
	// 1. Socket.closed will have error
	// 2. Socket.readable will be close without any data coming
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

/**
 * 
 * @param {string} base64Str 
 * @returns 
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		// go use modified Base64 for URL rfc4648 which js atob not support
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

/**
 * This is not real UUID validation
 * @param {string} uuid 
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

/**
 * Normally, WebSocket will not has exceptions when close.
 * @param {import("@cloudflare/workers-types").WebSocket} socket
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}

/**
 * @param {ArrayBuffer} udpChunk 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} vlessResponseHeader 
 * @param {(string)=> void} log 
 */
async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
	// no matter which DNS server client send, we alwasy use hard code one.
	// beacsue someof DNS server is not support DNS over TCP
	try {
		const dnsServer = '103.247.36.36'; // change to 1.1.1.1 after cf fix connect own ip bug
		const dnsPort = 53;
		/** @type {ArrayBuffer | null} */
		let vlessHeader = vlessResponseHeader;
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = connect({
			hostname: dnsServer,
			port: dnsPort,
		});

		log(`connected to ${dnsServer}:${dnsPort}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WS_READY_STATE_OPEN) {
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						webSocket.send(chunk);
					}
				}
			},
			close() {
				log(`dns server(${dnsServer}) tcp is close`);
			},
			abort(reason) {
				console.error(`dns server(${dnsServer}) tcp is abort`, reason);
			},
		}));
	} catch (error) {
		console.error(
			`handleDNSQuery have exception, error: ${error.message}`
		);
	}
}

/**
 * @param {number} addressType
 * @param {string} addressRemote
 * @param {number} portRemote
 * @param {function} log The logging function.
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
	const { username, password, hostname, port } = parsedSocks5Address;
	// Connect to the SOCKS server
	const socket = connect({
		hostname,
		port,
	});

	// Request head format (Worker -> Socks Server):
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	// https://en.wikipedia.org/wiki/SOCKS#SOCKS5
	// For METHODS:
	// 0x00 NO AUTHENTICATION REQUIRED
	// 0x02 USERNAME/PASSWORD https://datatracker.ietf.org/doc/html/rfc1929
	const socksGreeting = new Uint8Array([5, 2, 0, 2]);

	const writer = socket.writable.getWriter();

	await writer.write(socksGreeting);
	log('sent socks greeting');

	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	let res = (await reader.read()).value;
	// Response format (Socks Server -> Worker):
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	if (res[0] !== 0x05) {
		log(`socks server version error: ${res[0]} expected: 5`);
		return;
	}
	if (res[1] === 0xff) {
		log("no acceptable methods");
		return;
	}

	// if return 0x0502
	if (res[1] === 0x02) {
		log("socks server needs auth");
		if (!username || !password) {
			log("please provide username/password");
			return;
		}
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		const authRequest = new Uint8Array([
			1,
			username.length,
			...encoder.encode(username),
			password.length,
			...encoder.encode(password)
		]);
		await writer.write(authRequest);
		res = (await reader.read()).value;
		// expected 0x0100
		if (res[0] !== 0x01 || res[1] !== 0x00) {
			log("fail to auth socks server");
			return;
		}
	}

	// Request data format (Worker -> Socks Server):
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// ATYP: address type of following address
	// 0x01: IPv4 address
	// 0x03: Domain name
	// 0x04: IPv6 address
	// DST.ADDR: desired destination address
	// DST.PORT: desired destination port in network octet order

	// addressType
	// 1--> ipv4  addressLength =4
	// 2--> domain name
	// 3--> ipv6  addressLength =16
	let DSTADDR;	// DSTADDR = ATYP + DST.ADDR
	switch (addressType) {
		case 1:
			DSTADDR = new Uint8Array(
				[1, ...addressRemote.split('.').map(Number)]
			);
			break;
		case 2:
			DSTADDR = new Uint8Array(
				[3, addressRemote.length, ...encoder.encode(addressRemote)]
			);
			break;
		case 3:
			DSTADDR = new Uint8Array(
				[4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
			);
			break;
		default:
			log(`invild  addressType is ${addressType}`);
			return;
	}
	const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
	await writer.write(socksRequest);
	log('sent socks request');

	res = (await reader.read()).value;
	// Response format (Socks Server -> Worker):
	//  +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	if (res[1] === 0x00) {
		log("socks connection opened");
	} else {
		log("fail to open socks connection");
		return;
	}
	writer.releaseLock();
	reader.releaseLock();
	return socket;
}

/**
 * @param {string} address
 */
function socks5AddressParser(address) {
	let [latter, former] = address.split("@").reverse();
	let username, password, hostname, port;
	if (former) {
		const formers = former.split(":");
		if (formers.length !== 2) {
			throw new Error('Invalid SOCKS address format');
		}
		[username, password] = formers;
	}
	const latters = latter.split(":");
	port = Number(latters.pop());
	if (isNaN(port)) {
		throw new Error('Invalid SOCKS address format');
	}
	hostname = latters.join(":");
	const regex = /^\[.*\]$/;
	if (hostname.includes(":") && !regex.test(hostname)) {
		throw new Error('Invalid SOCKS address format');
	}
	return {
		username,
		password,
		hostname,
		port,
	}
}

/**
 * @param {string} userID 
 * @param {string | null} hostName
 * @returns {string}
 */
function getVLESSConfig(userID, hostName) {
	const vlessMain = `vless://${userID}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`
	return `
################################################################
v2ray
---------------------------------------------------------------
${vlessMain}
---------------------------------------------------------------
################################################################
clash-meta
---------------------------------------------------------------
- type: vless
  name: ${hostName}
  server: ${hostName}
  port: 443
  uuid: ${userID}
  network: ws
  tls: true
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
    path: "/?ed=2048"
    headers:
      host: ${hostName}
---------------------------------------------------------------
################################################################
`;
}

/**
 * 根据CIDR格式的字符串生成所有IP地址。
 * @param {string} cidr - CIDR格式的字符串，例如"192.168.0.1/24"。
 * @returns {Array<string>} 由所有子网IP地址组成的数组。如果输入不是有效的CIDR格式，则返回空数组。
 */
function generateAllIpsFromCidr(cidr) {
	// 匹配CIDR格式，确保输入有效
	const cidrMatch = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
	if (!cidrMatch) return [];

	const baseIp = cidrMatch[1]; // 基本IP地址
	const subnetMask = Number(cidrMatch[2]); // 子网掩码，转换为数字
	const ipArray = baseIp.split('.').map(Number); // 将基本IP地址转换为数字数组
	const maskBits = 32 - subnetMask; // 计算掩码位数
	const maxSubnetSize = Math.pow(2, maskBits) - 2; // 计算子网中可分配的最大IP数，排除网络地址和广播地址

	// 将基本IP地址转换为一个32位的数字
	const baseIpNum = ipArray.reduce((sum, num, idx) => sum + (num << ((3 - idx) * 8)), 0);
	const ips = [];
	// 循环生成所有有效IP地址
	for (let i = 1; i <= maxSubnetSize; i++) {
		const ipNum = baseIpNum + i; // 根据索引生成IP地址数字
		// 将数字IP地址转换为点分十进制字符串
		const ip = [(ipNum >>> 24) & 255, (ipNum >>> 16) & 255, (ipNum >>> 8) & 255, ipNum & 255].join('.');
		ips.push(ip); // 添加到结果数组
	}

	return ips;
}

/**
 * 从CIDR列表生成指定数量的随机IP地址数组。
 * @param {Array} cidrList - CIDR格式的IP地址范围列表，例如["192.168.0.0/24", "10.0.0.0/16"]。
 * @param {number} count - 需要生成的随机IP地址数量。
 * @returns {Array} - 包含指定数量且不重复的随机IP地址的数组。
 */
function randomIpsFromCidrList(cidrList, count) {
	// 将CIDR列表中的每个范围转换为所有可能的IP地址，并合并为一个数组
	const allIps = cidrList.map(generateAllIpsFromCidr).flat();
	const uniqueIps = new Set(); // 使用Set存储唯一IP地址

	// 循环，直到获取到足够数量的不重复IP地址
	while (uniqueIps.size < count && uniqueIps.size < allIps.length) {
		// 随机选择一个数组索引，将该IP地址添加到uniqueIps集合中
		const randomIndex = Math.floor(Math.random() * allIps.length);
		uniqueIps.add(allIps[randomIndex]);
	}

	// 将Set转换为数组并返回
	return [...uniqueIps];
}

/**
 * 将IPv4地址转换成数字表示形式。
 * @param {string} ip - IPv4地址，格式为xxx.xxx.xxx.xxx，其中xxx为0-255之间的整数。
 * @returns {number} - 返回对应IPv4地址的数字表示形式。
 */
function ipToNumber(ip) {
	// 通过'.'将IPv4地址分割成四部分，然后累加每个部分的十进制数值，最终得到数字表示形式
	return ip.split('.').reduce((acc, octet) => acc * 256 + parseInt(octet, 10), 0);
}

/**
 * 对IP地址数组进行排序(可以排序非IP地址的)
 * @param {string[]} ipAddresses - 包含IP地址的字符串数组。
 * @return {string[]} - 返回按IP地址数字值升序排序后的数组。
 */
function sortIpAddresses(ipAddresses) {
	// 使用ipToNumber转换函数将IP地址转换为数字，对于非IP地址的字符串直接使用比较函数
	return ipAddresses.sort((a, b) => {
		if (isValidIpAddress(a) && isValidIpAddress(b)) {
			// 如果两者都是IP地址，则按数字值排序
			return ipToNumber(a) - ipToNumber(b);
		} else if (!isValidIpAddress(a) && !isValidIpAddress(b)) {
			// 如果两者都不是IP地址，则按字符串字典顺序排序
			return a.localeCompare(b);
		} else {
			// 如果一个是IP地址，另一个不是，则总是将非IP地址的字符串排在前面
			return isValidIpAddress(a) ? 1 : -1;
		}
	});
}

/**
 * 检查给定的字符串是否是有效的IPv4地址。
 * @param {string} ip - 待检查的IP地址字符串。
 * @returns {boolean} - 如果给定的IP地址有效，则返回true；否则返回false。
 */
function isValidIpAddress(ip) {
	// 通过'.'将IP地址分割成四部分
	const parts = ip.split('.');
	// 检查分割后的部分是否满足以下条件：长度为4，且每个部分都是0-255之间的整数
	return (
		parts.length === 4 &&
		parts.every(part => /^\d+$/.test(part) && parseInt(part, 10) >= 0 && parseInt(part, 10) <= 255)
	);
}

/**
 * 
 * @param {string} ipaddrURL - 要抓取网页的内容
 * @returns {string} - 返回网页的全部内容
 */
async function fetchWebPageContent(URL) {
	try {
		const response = await fetch(URL);
		if (!response.ok) {
			throw new Error(`Failed to get: ${response.status}`);
			return "";
		} else {
			return await response.text();
		}
	} catch (err) {
		console.error(`Failed to fetch ${URL} web conten: ${err.message}`);
		return "";
	}

}

/**
 * 
 * @param {string} cidrParam - 从get请求链接中，获取cidr参数的cidr值(支持多个cidr传入，用逗号分割)
 * @returns {Array} - 返回cidrs范围内IP数组（IP一定不重复，且在cidrs数组里面cidr范围内，数量最多1000个，取决于cidr的范围）
 */
function getCidrParamAndGenerateIps(cidrParam) {
	let cidrs = [];
	let vlessArray = []; // 接收结果（数组）
	if (cidrParam.includes(',')) {
		cidrs = cidrParam.split(','); // url传入的cidr有多个
	} else {
		cidrs = [cidrParam]; // url传入的cidr只有一个
	}
	const randomIps = randomIpsFromCidrList(cidrs, 1000); // 从cidrs数组中的哪些cidr中随机选取1000个ip
	return randomIps;
}

/**
 * 遍历ipsArray数组，生成vless链接，返回vless链接的数组
 * @param {Array} ipsArray - 包含大量IP的数组
 * @param {string} hostName - sni、headers.host的地址
 * @param {string} port - 端口
 * @param {string} path - vless配置中的path
 * @param {string} userID - uuid
 * @returns {Array} - 返回vless的数组
 */
function eachIpsArrayAndGenerateVless(ipsArray, hostName, port, path, userID) {
	let vlessArray = [];
	for (let i = 0; i < ipsArray.length; i++) {
		const ipaddr = ipsArray[i].trim();
		let vlessMain;
		if (ipaddr && hostName.includes("workers.dev")) { // workers.dev域名不支持tls
			vlessMain = `vless://${userID}@${ipaddr}:${port}?encryption=none&security=none&type=ws&host=${hostName}&path=${path}#${ipaddr}:${port}`;
		} else if (ipaddr) { // 其他域名支持tls
			vlessMain = `vless://${userID}@${ipaddr}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${path}#${ipaddr}:${port}`;
		}
		if (vlessMain) {
			vlessArray.push(vlessMain);
		}
	}
	return vlessArray;
}

/**
 * 将一个数组分割成多个指定大小的子数组。
 * @param {Array} array - 需要分割的原始数组。
 * @param {number} chunkSize - 指定的子数组大小。
 * @returns {Array} 返回一个包含多个指定大小子数组的数组。
 */
function splitArray(array, chunkSize) {
	const chunks = []; // 用于存放分割后子数组的数组
	let index = 0; // 初始化索引值
	while (index < array.length) {
		// 将数组从当前索引到当前索引加上块大小的元素切分为子数组，推入chunks中
		chunks.push(array.slice(index, index + chunkSize));
		index += chunkSize; // 更新索引值，为下一次切分准备
	}
	return chunks;
}

/**
 * 将数组平均分割成多个小数组。
 * @param {Array} array - 需要分割的原始数组。
 * @param {number} maxChunkSize - 最大块大小，分割后每个块的最大长度。
 * @returns {Array} 返回由平均分割后的子数组组成的数组。
 */
function splitArrayEvenly(array, maxChunkSize) {
	// 计算原始数组的总长度
	const totalLength = array.length;
	// 计算需要分割成的块数，向上取整确保每个块大小尽量均匀
	const numChunks = Math.ceil(totalLength / maxChunkSize);
	// 根据块数计算每个块的实际大小，也需向上取整以保证分割均匀
	const chunkSize = Math.ceil(totalLength / numChunks);
	// 调用splitArray函数将数组按计算出的块大小进行分割
	return splitArray(array, chunkSize);
}