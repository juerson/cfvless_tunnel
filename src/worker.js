import { connect } from 'cloudflare:sockets';

let userID = '0648919d-8bf1-4d4c-8525-36cf487506ec'; // 备用UUID
let landingAddress = ''; // 备用代理IP地址

// 备用socks5代理地址，socks5Address优先于landingAddress（格式:  user:pass@host:port、:@host:port）
let socks5Address = '';

// —————————————————————————————————————————— 该参数用于访问GitHub的私有仓库文件 ——————————————————————————————————————————
const DEFAULT_GITHUB_TOKEN = ''; // GitHub的令牌
const DEFAULT_OWNER = ''; // GitHub的用户名
const DEFAULT_REPO = ''; // GitHub的仓库名
const DEFAULT_BRANCH = 'main'; // GitHub的分支名
const DEFAULT_FILE_PATH = 'README.md'; // GitHub的文件路径
// —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

let clashTemplateUrl = 'https://raw.githubusercontent.com/juerson/cfvless_tunnel/refs/heads/master/clash_template.yaml'; // clash模板
let ipaddrURL = 'https://raw.githubusercontent.com/juerson/cfvless_tunnel/refs/heads/master/ipaddr.txt';
let dohURL = 'https://dns.google.com/resolve';

/**
 * 1、查看节点配置信息的密码：http://your_worker_domain/config?pwd={CONFIG_PASSWORD}
 *
 * 2、查看订阅的密码：
 *        https://your_worker_domain/sub?pwd={SUB_PASSWORD}&target={v2 or clash}
 *    可选参数（一个或多个），顺序不固定：
 *        &page=1&id={your_vless_uuid}&port={port}&cidr={cidr}&path={your_vess_path}&hostName={your_worker_domain}
 */
let configPassword = ''; // 备用
let subPassword = ''; // 备用

const HTTP_WITH_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
const HTTPS_WITH_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

const domainList = [
	'https://www.iq.com',
	'https://www.dell.com',
	'https://www.bilibili.com',
	'https://www.wix.com/',
	'https://landingsite.ai/',
	'https://vimeo.com/',
	'https://www.pexels.com/',
	'https://www.revid.ai/',
];

let parsedSocks5Address = {};
let enableSocks = false;

export default {
	async fetch(request, env, ctx) {
		try {
			userID = env.UUID4 || userID;
			landingAddress = env.LANDING_ADDRESS || landingAddress;
			socks5Address = env.SOCKS5 || socks5Address;
			configPassword = env.CONFIG_PASSWORD || configPassword;
			subPassword = env.SUB_PASSWORD || subPassword;
			dohURL = env.DOH_URL || dohURL;

			// ———————————————————————————— 访问GitHub的私有仓库文件 ————————————————————————————
			const GITHUB_TOKEN = env.GITHUB_TOKEN || DEFAULT_GITHUB_TOKEN;
			const OWNER = env.GITHUB_OWNER || DEFAULT_OWNER;
			const REPO = env.GITHUB_REPO || DEFAULT_REPO;
			const BRANCH = env.GITHUB_BRANCH || DEFAULT_BRANCH;
			const FILE_PATH = env.GITHUB_FILE_PATH || DEFAULT_FILE_PATH;
			// ————————————————————————————————————————————————————————————————————————————————

			// 检查字符串中是否含逗号，有的就随机从中选择一个元素
			if (landingAddress.includes(',')) {
				const arr = landingAddress.split(',');
				const randomIndex = Math.floor(Math.random() * arr.length);
				landingAddress = arr[randomIndex].trim();
			} else {
				landingAddress = landingAddress.trim();
			}
			if (socks5Address) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Address);
					enableSocks = true;
				} catch (err) {
					// console.log(err.toString());
					enableSocks = false;
				}
			}
			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				switch (url.pathname) {
					case '/':
						const randomDomain = domainList[Math.floor(Math.random() * domainList.length)];
						const redirectResponse = new Response('', {
							status: 301,
							headers: {
								Location: randomDomain,
							},
						});
						return redirectResponse;
					case `/config`: {
						// 接收地址中传入的pwd参数值
						let password = url.searchParams.get('pwd') || '';
						if (password) {
							password = encodeURIComponent(password);
							configPassword = encodeURIComponent(configPassword);
						}
						// 检查地址栏中传入的pwd密码跟环境变量的CONFIG_PASSWORD密码是否一致，一致才能查看节点的配置信息
						if (configPassword === password) {
							const baseConfig = getBaseConfig(userID, request.headers.get('Host'));
							return new Response(`${baseConfig}`, {
								status: 200,
								headers: {
									'Content-Type': 'text/plain;charset=utf-8',
								},
							});
						} else {
							return new Response('Not found', { status: 404 });
						}
					}
					case `/sub`:
						let password = url.searchParams.get('pwd') || ''; // (必须的)接收pwd参数(password密码的简写)，不传入pwd参数则不能查看对应的配置信息
						let target = url.searchParams.get('target'); // (必须的)接收target参数，指向什么订阅？v2ray or clash?
						let hostName = url.searchParams.get('hostName') || url.hostname; // 接收hostName参数，没有则使用当前网页的域名，可选的（填充到vless中的sni和host）
						userID = url.searchParams.get('id') || userID; // 接收id参数，没有则使用默认值，可选的
						let portParam = url.searchParams.get('port') || 0; // 接收port参数，可选的
						let pathParam = url.searchParams.get('path'); // 接收path参数，可选的
						let cidrParam = url.searchParams.get('cidr'); // 就收cidr参数，可选的，如：cidr=104.21.192.0/19,104.21.64.0/19

						// 检查地址栏中传入的pwd密码，跟环境变量的SUB_PASSWORD密码是否一致，一才能能查看/执行订阅的代码
						if (password) {
							password = encodeURIComponent(password);
							subPassword = encodeURIComponent(subPassword);
						}
						if (!isValidUUID(userID)) {
							throw new Error('uuid4 is not valid');
						}
						// 对path进行url编码，没有path参数则使用默认值
						let path = pathParam ? encodeURIComponent(pathParam) : '%2F%3Fed%3D2048';
						let ipsArray = []; // 后面vless、clash中要使用到

						// 获取订阅需要的优选CDN IP，后面需要它构建节点信息
						if (!cidrParam && password === subPassword) {
							let ips_string = '';
							try {
								// 读取 GitHub 私有仓库的优选IP或域名，读取不到就默认为空字符串
								const fileContent = await fetchGitHubFile(GITHUB_TOKEN, OWNER, REPO, FILE_PATH, BRANCH);
								const decoder = new TextDecoder('utf-8');
								ips_string = decoder.decode(fileContent.body);
							} catch (error) {
								// console.log(`Error: ${error.message}`);
							}
							// 如果读取到GitHub私有文件的内容空时，就使用ipaddrURL的IP地址
							ips_string = ips_string !== '' ? ips_string : await fetchWebPageContent(ipaddrURL);
							let ips_Array = ips_string
								.trim()
								.split(/\r\n|\n|\r/)
								.map((ip) => ip.trim());
							ipsArray = sortIpAddresses(ips_Array); // 按照IP排序，便于后面分页显示
						} else if (cidrParam && password === subPassword) {
							ipsArray = getCidrParamAndGenerateIps(cidrParam); // 使用get请求中的cidr参数值生成ip地址(最多1000个，顺序随机)
						} else {
							return new Response('Not found', { status: 404 }); // 密码错误，显示Not found
						}
						let page = url.searchParams.get('page') || 1; // 从1开始的页码
						if (target === 'v2' || target === base64ToUtf8('djJyYXk')) {
							/**
							 * 分页创建vless节点：防止太多节点，全部生成到一个vless配置文件，导致浏览器、v2rayN等客户端卡死
							 *
							 * Page参数：页码，必须是整数，默认为1，从1开始，超出页码范围(由程序动态计算)则显示Not found，每页可以单独使用
							 * maxNode参数：每页最多的节点数
							 *
							 */
							let maxNodeNumber = url.searchParams.get('maxNode') || 1000; // 获取get请求链接中的maxNode参数(最大节点数)
							maxNodeNumber = maxNodeNumber > 0 && maxNodeNumber <= 5000 ? maxNodeNumber : 1000; // 限制最大节点数
							// splitArrayEvenly函数：ipArray数组分割成每个子数组都不超过maxNode的数组(子数组之间元素个数平均分配)
							let chunkedArray = splitArrayEvenly(ipsArray, maxNodeNumber);
							let totalPage = Math.ceil(ipsArray.length / maxNodeNumber); // 计算总页数
							// 剔除不合法的，页码超出范围，返回404
							if (page > totalPage || page < 1) {
								return new Response('Not found', { status: 404 });
							}
							// 使用哪个子数组的数据？
							let ipsArrayChunked = chunkedArray[page - 1];
							// 遍历ipsArray生成vless链接
							let reusltArray = eachIpsArrayAndGeneratevess(ipsArrayChunked, hostName, portParam, path, userID);
							let vessArrayStr = reusltArray.join('\n');
							// base64编码
							let encoded = btoa(vessArrayStr);
							return new Response(encoded, { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
						} else if (target === base64ToUtf8('Y2xhc2g') || target === base64ToUtf8('bWlob21v')) {
							/**
							 * 分页创建clash/mihomo配置文件，参数的意思跟前面的v2ray一样
							 */
							let maxNode = url.searchParams.get('maxNode') || 300;
							maxNode = maxNode > 0 && maxNode <= 1000 ? maxNode : 300;
							let chunkedArray = splitArrayEvenly(ipsArray, maxNode);
							let totalPage = Math.ceil(ipsArray.length / maxNode);
							if (page > totalPage || page < 1) {
								return new Response('Not found', { status: 404 });
							}
							// 抓取clash配置模板
							let clashTemplate = await fetchWebPageContent(clashTemplateUrl);
							let ipsArrayChunked = chunkedArray[page - 1];
							let proxyies = [];
							let nodeNameArray = [];

							// clash的json配置的样子
							const base64String =
								'eyJ0eXBlIjoidmxlc3MiLCJuYW1lIjoiIiwic2VydmVyIjoiIiwicG9ydCI6NDQzLCJ1dWlkIjoiI3V1aWQ0IyIsIm5ldHdvcmsiOiJ3cyIsInRscyI6dHJ1ZSwidWRwIjpmYWxzZSwic2VydmVybmFtZSI6IiIsImNsaWVudC1maW5nZXJwcmludCI6ImNocm9tZSIsIndzLW9wdHMiOnsicGF0aCI6IiNwYXRoIyIsImhlYWRlcnMiOnsiSG9zdCI6IiNIb3N0IyJ9fX0';
							// 1. 解码Base64字符串
							const decodedString = base64ToUtf8(base64String);
							// 2. 使用 decodeURIComponent 处理解码后的字符串
							const uriDecodedString = decodeURIComponent(decodedString);

							for (let i = 0; i < ipsArrayChunked.length; i++) {
								let ipaddr = ipsArrayChunked[i];

								let randomHttpPortElement = getRandomElement(HTTP_WITH_PORTS);
								let randomHttpsPortElement = getRandomElement(HTTPS_WITH_PORTS);
								let port =
									([0, ...HTTPS_WITH_PORTS].includes(Number(portParam)) && hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY='))) ||
									([0, ...HTTP_WITH_PORTS].includes(Number(portParam)) && !hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')))
										? hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY='))
											? randomHttpPortElement
											: randomHttpsPortElement
										: portParam;
								let nodeName = `${ipaddr}:${port}`;

								// 3. 将解码后的字符串转换为JSON对象
								const jsonObject = JSON.parse(uriDecodedString);
								// 4. 修改JSON对象中的值
								jsonObject.name = nodeName;
								jsonObject.server = ipaddr;
								jsonObject.port = port;
								jsonObject.servername = hostName;
								// 要替换的字符串(另一种方法修改)
								let replacements = {
									'#uuid4#': userID,
									'#Host#': hostName,
									'#path#': decodeURIComponent(path),
								};

								if (hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY='))) {
									jsonObject.tls = false;
									delete jsonObject.servername;
								}

								let modifiedResult = Object.entries(replacements).reduce((acc, [key, value]) => {
									return acc.replace(new RegExp(key, 'g'), value);
								}, `  - ${JSON.stringify(jsonObject)}`);
								proxyies.push(modifiedResult);
								nodeNameArray.push(nodeName);
							}
							// 替换clash模板中的对应的字符串，生成clash配置文件
							let replaceProxyies = clashTemplate.replace(
								new RegExp(
									atob(
										'ICAtIHtuYW1lOiAwMSwgc2VydmVyOiAxMjcuMC4wLjEsIHBvcnQ6IDgwLCB0eXBlOiBzcywgY2lwaGVyOiBhZXMtMTI4LWdjbSwgcGFzc3dvcmQ6IGExMjM0NTZ9'
									),
									'g'
								),
								proxyies.join('\n')
							);
							let clashConfig = replaceProxyies.replace(
								new RegExp(atob('ICAgICAgLSAwMQ=='), 'g'),
								nodeNameArray.map((ipWithPort) => `      - ${ipWithPort}`).join('\n')
							);
							return new Response(clashConfig, { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
						} else if (target === base64ToUtf8('c2luZ2JveA')) {
							// 以下用于生成singbox配置
							let maxNode = url.searchParams.get('maxNode') || 50;
							maxNode = maxNode > 0 && maxNode <= 100 ? maxNode : 50;
							let chunkedArray = splitArrayEvenly(ipsArray, maxNode);
							let totalPage = Math.ceil(ipsArray.length / maxNode);
							if (page > totalPage || page < 1) {
								return new Response('Not found', { status: 404 });
							}
							let ipsArrayChunked = chunkedArray[page - 1];
							let singbxnodes = [];
							let singbxtagname = []; // tag的名称，用于代理分组，这里省略后续相关，可以删除它
							for (let i = 0; i < ipsArrayChunked.length; i++) {
								let ipaddr = ipsArrayChunked[i];
								let randomHttpPortElement = getRandomElement(HTTP_WITH_PORTS);
								let randomHttpsPortElement = getRandomElement(HTTPS_WITH_PORTS);
								let port =
									([0, ...HTTPS_WITH_PORTS].includes(Number(portParam)) && hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY='))) ||
									([0, ...HTTP_WITH_PORTS].includes(Number(portParam)) && !hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')))
										? hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY='))
											? randomHttpPortElement
											: randomHttpsPortElement
										: portParam;
								let nodeName = `${ipaddr}:${port}`;
								let onTls = hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')) ? false : true;
								let base64JsonString =
									'ICAgIHsNCiAgICAgICJuZXR3b3JrIjogInRjcCIsDQogICAgICAic2VydmVyIjogIiNzZXJ2ZXIjIiwNCiAgICAgICJzZXJ2ZXJfcG9ydCI6ICNwb3J0IywNCiAgICAgICJ0YWciOiAiI3RhZ25hbWUjIiwNCiAgICAgICJ0bHMiOiB7DQogICAgICAgICJlbmFibGVkIjogI29uVGxzIywNCiAgICAgICAgImluc2VjdXJlIjogdHJ1ZSwNCiAgICAgICAgInNlcnZlcl9uYW1lIjogIiNIb3N0IyIsDQogICAgICAgICJ1dGxzIjogew0KICAgICAgICAgICJlbmFibGVkIjogdHJ1ZSwNCiAgICAgICAgICAiZmluZ2VycHJpbnQiOiAiY2hyb21lIg0KICAgICAgICB9DQogICAgICB9LA0KICAgICAgInRyYW5zcG9ydCI6IHsNCiAgICAgICAgImVhcmx5X2RhdGFfaGVhZGVyX25hbWUiOiAiU2VjLVdlYlNvY2tldC1Qcm90b2NvbCIsDQogICAgICAgICJoZWFkZXJzIjogew0KICAgICAgICAgICJIb3N0IjogIiNIb3N0IyINCiAgICAgICAgfSwNCiAgICAgICAgInBhdGgiOiAiI3BhdGgjIiwNCiAgICAgICAgInR5cGUiOiAid3MiDQogICAgICB9LA0KICAgICAgInR5cGUiOiAidmxlc3MiLA0KICAgICAgInV1aWQiOiAiI3V1aWQ0IyINCiAgICB9';
								// 要替换的字符串
								let replacements = {
									'#server#': ipaddr,
									'#port#': port,
									'#uuid4#': userID,
									'#Host#': hostName,
									'#onTls#': onTls,
									'#path#': decodeURIComponent(path),
									'#tagname#': nodeName,
								};

								let singbxNode = Object.entries(replacements).reduce((acc, [key, value]) => {
									return acc.replace(new RegExp(key, 'g'), value);
								}, base64ToUtf8(base64JsonString));
								singbxnodes.push(singbxNode);
								singbxtagname.push(nodeName);
							}
							let singbxconfig = base64ToUtf8('ew0KICAib3V0Ym91bmRzIjogWw0KI291dGJkcyMNCiAgXQ0KfQ').replace(
								'#outbds#',
								singbxnodes.join(',\n')
							);
							return new Response(singbxconfig, { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
						}
					default:
						return new Response('Not found', { status: 404 });
				}
			} else {
				const pathString = url.pathname;
				// 从v2rayN客户端的path中，提取并修改原来的landingAddress或socks5的地址
				if (pathString.includes('/pyip=')) {
					const pathpathLandingaddr = pathString.split('=')[1];
					if (isValidlandingAddress(pathpathLandingaddr)) {
						landingAddress = pathpathLandingaddr;
					}
				} else if (pathString.includes('/socks=')) {
					const pathSocks = pathString.split('=')[1];
					const matchSocks = (socksAddress) => {
						// 后面这些情况都能准确提取socks地址。例如：socks://127.0.0.1:8080、socks://user:pass@127.0.0.1:8080、user:pass@127.0.0.1:8080、127.0.0.1:8080
						const regex =
							/^(?:socks:\/\/)?(?:([a-zA-Z0-9._%+-]+):([a-zA-Z0-9._%+-]+)@)?([0-9]{1,3}(?:\.[0-9]{1,3}){3}:\d+|[a-zA-Z0-9.-]+:\d+)$/;
						const match = socksAddress.match(regex);
						if (match) {
							const [_, username, password, address] = match;
							// 返回有用户认证的"user:pass@host:port"、无用户认证的":@host:port"
							return username && password ? `${username}:${password}@${address}` : `:@${address}`;
						}
						return '';
					};
					let socksAddress = matchSocks(pathSocks);
					if (socksAddress.length !== 0) {
						parsedSocks5Address = socks5AddressParser(socksAddress); // 解析socks5地址，{ username, password, hostname, port }
						enableSocks = true; // 开启socks，使用socks5代理
					}
				}
				return await a1(request);
			}
		} catch (err) {
			return new Response(err.toString());
		}
	},
};

async function a1(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();
	let address = '';
	let portWithRandomLog = '';
	const log = (info, event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
	let remoteSocketWapper = {
		value: null,
	};
	let isDns = false;
	let udpStreamWrite = null;
	readableWebSocketStream
		.pipeTo(
			new WritableStream({
				async write(chunk, controller) {
					if (isDns && udpStreamWrite) {
						return udpStreamWrite(chunk);
					}
					if (remoteSocketWapper.value) {
						const writer = remoteSocketWapper.value.writable.getWriter();
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
						vessVersion = new Uint8Array([0, 0]),
						isUDP,
					} = processvessHeader(chunk, userID);
					address = addressRemote;
					portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '}`;
					if (hasError) {
						throw new Error(message);
						return;
					}
					if (isUDP) {
						if (portRemote === 53) {
							isDns = true;
						} else {
							throw new Error('UDP proxy only enable for DNS which is port 53');
							return;
						}
					}
					const vessResponseHeader = new Uint8Array([vessVersion[0], 0]);
					const rawClientData = chunk.slice(rawDataIndex);
					if (isDns) {
						const { write } = await handleUDPOutBound(webSocket, vessResponseHeader, log);
						udpStreamWrite = write;
						udpStreamWrite(rawClientData);
						return;
					}
					handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vessResponseHeader, log);
				},
				close() {
					// log(`readableWebSocketStream is close`);
				},
				abort(reason) {
					// log(`readableWebSocketStream is abort`, JSON.stringify(reason));
				},
			})
		)
		.catch((err) => {
			// log('readableWebSocketStream pipeTo error', err);
		});
	return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vessResponseHeader, log) {
	async function connectAndWrite(address, port, socks = false) {
		const tcpSocket = socks
			? await socks5Connect(addressType, address, port, log)
			: connect({
					hostname: address,
					port: port,
			  });
		remoteSocket.value = tcpSocket;
		// log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

	async function retry() {
		if (enableSocks) {
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			// 分离landingAddress的host和port端口
			let pxAddressJSON = parselandingAddress(landingAddress);
			tcpSocket = await connectAndWrite(pxAddressJSON.host || addressRemote, pxAddressJSON.port || portRemote);
		}
		tcpSocket.closed
			.catch((error) => {
				// console.log('retry tcpSocket closed error', error);
			})
			.finally(() => {
				safeCloseWebSocket(webSocket);
			});
		remoteSocketToWS(tcpSocket, webSocket, vessResponseHeader, null, log);
	}

	let tcpSocket = await connectAndWrite(addressRemote, portRemote);
	remoteSocketToWS(tcpSocket, webSocket, vessResponseHeader, retry, log);
}

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

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});
			webSocketServer.addEventListener('error', (err) => {
				// log('webSocketServer has error');
				controller.error(err);
			});
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
			if (readableStreamCancel) {
				return;
			}
			// log(`ReadableStream was canceled, due to ${reason}`);
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		},
	});

	return stream;
}

function processvessHeader(vessBuffer, userID) {
	if (vessBuffer.byteLength < 24) {
		return { hasError: true, message: 'invalid data' };
	}
	const version = new Uint8Array(vessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	if (stringify(new Uint8Array(vessBuffer.slice(1, 17))) === userID) {
		isValidUser = true;
	}
	if (!isValidUser) {
		return { hasError: true, message: 'invalid user' };
	}

	const optLength = new Uint8Array(vessBuffer.slice(17, 18))[0];
	const command = new Uint8Array(vessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
	if (command === 1) {
		//
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vessBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);
	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(vessBuffer.slice(addressIndex, addressIndex + 1));

	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(vessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(vessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(vessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(vessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `invild  addressType is ${addressType}` };
	}
	if (!addressValue) {
		return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vessVersion: version,
		isUDP,
	};
}

async function remoteSocketToWS(remoteSocket, webSocket, vessResponseHeader, retry, log) {
	let remoteChunkCount = 0;
	let chunks = [];
	let vessHeader = vessResponseHeader;
	let hasIncomingData = false;
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
					//
				},
				async write(chunk, controller) {
					hasIncomingData = true;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error('webSocket.readyState is not open, maybe close');
					}
					if (vessHeader) {
						webSocket.send(await new Blob([vessHeader, chunk]).arrayBuffer());
						vessHeader = null;
					} else {
						webSocket.send(chunk);
					}
				},
				close() {
					// log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(`remoteSocketToWS has exception `, error.stack || error);
			safeCloseWebSocket(webSocket);
		});

	if (hasIncomingData === false && retry) {
		// log(`retry`);
		retry();
	}
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

function isValidUUID(uuid4) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid4);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

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
	return (
		byteToHex[arr[offset + 0]] +
		byteToHex[arr[offset + 1]] +
		byteToHex[arr[offset + 2]] +
		byteToHex[arr[offset + 3]] +
		'-' +
		byteToHex[arr[offset + 4]] +
		byteToHex[arr[offset + 5]] +
		'-' +
		byteToHex[arr[offset + 6]] +
		byteToHex[arr[offset + 7]] +
		'-' +
		byteToHex[arr[offset + 8]] +
		byteToHex[arr[offset + 9]] +
		'-' +
		byteToHex[arr[offset + 10]] +
		byteToHex[arr[offset + 11]] +
		byteToHex[arr[offset + 12]] +
		byteToHex[arr[offset + 13]] +
		byteToHex[arr[offset + 14]] +
		byteToHex[arr[offset + 15]]
	).toLowerCase();
}
function stringify(arr, offset = 0) {
	const uuid4 = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid4)) {
		throw TypeError('Stringified UUID4 is invalid');
	}
	return uuid4;
}

async function handleUDPOutBound(webSocket, vessResponseHeader, log) {
	let isvessHeaderSent = false;

	const transformStream = new TransformStream({
		start(controller) {},
		transform(chunk, controller) {
			// udp message 2 byte is the the length of udp data
			// TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
			for (let index = 0; index < chunk.byteLength; ) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {},
	});

	// only handle dns udp for now
	transformStream.readable
		.pipeTo(
			new WritableStream({
				async write(chunk) {
					// e.g: dohURL = 'https://1.1.1.1/dns-query';
					const resp = await fetch(dohURL, {
						method: 'POST',
						headers: {
							'content-type': 'application/dns-message',
						},
						body: chunk,
					});
					const dnsQueryResult = await resp.arrayBuffer();
					const udpSize = dnsQueryResult.byteLength;
					const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
					if (webSocket.readyState === WS_READY_STATE_OPEN) {
						// log(`doh success and dns message length is ${udpSize}`);
						if (isvessHeaderSent) {
							webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
						} else {
							webSocket.send(await new Blob([vessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
							isvessHeaderSent = true;
						}
					}
				},
			})
		)
		.catch((error) => {
			// log('dns udp has error' + error);
		});

	const writer = transformStream.writable.getWriter();

	return {
		write(chunk) {
			writer.write(chunk);
		},
	};
}

async function socks5Connect(addressType, addressRemote, portRemote, log) {
	const { username, password, hostname, port } = parsedSocks5Address;
	const socket = connect({ hostname, port });
	const socksGreeting = new Uint8Array([5, 2, 0, 2]);
	const writer = socket.writable.getWriter();
	await writer.write(socksGreeting);
	// log('sent socks greeting');

	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	let res = (await reader.read()).value;
	if (res[0] !== 0x05) {
		// log(`socks server version error: ${res[0]} expected: 5`);
		return;
	}
	if (res[1] === 0xff) {
		// log('no acceptable methods');
		return;
	}

	if (res[1] === 0x02) {
		// log('socks server needs auth');
		if (!username || !password) {
			// log('please provide username/password');
			return;
		}
		const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
		await writer.write(authRequest);
		res = (await reader.read()).value;
		if (res[0] !== 0x01 || res[1] !== 0x00) {
			// log('fail to auth socks server');
			return;
		}
	}

	let DSTADDR;
	switch (addressType) {
		case 1:
			DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
			break;
		case 2:
			DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
			break;
		case 3:
			DSTADDR = new Uint8Array([4, ...addressRemote.split(':').flatMap((x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
			break;
		default:
			// log(`invild  addressType is ${addressType}`);
			return;
	}
	const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
	await writer.write(socksRequest);
	// log('sent socks request');
	res = (await reader.read()).value;
	if (res[1] === 0x00) {
		// log('socks connection opened');
	} else {
		// log('fail to open socks connection');
		return;
	}
	writer.releaseLock();
	reader.releaseLock();
	return socket;
}

function socks5AddressParser(address) {
	let [latter, former] = address.split('@').reverse();
	let username, password, hostname, port;
	if (former) {
		const formers = former.split(':');
		if (formers.length !== 2) {
			throw new Error('Invalid SOCKS address format');
		}
		[username, password] = formers;
	}
	const latters = latter.split(':');
	port = Number(latters.pop());
	if (isNaN(port)) {
		throw new Error('Invalid SOCKS address format');
	}
	hostname = latters.join(':');
	const regex = /^\[.*\]$/;
	if (hostname.includes(':') && !regex.test(hostname)) {
		throw new Error('Invalid SOCKS address format');
	}
	return { username, password, hostname, port };
}

/**
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */
function getBaseConfig(userID, hostName) {
	let server = 'www.visa.com.sg';
	let port = hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')) ? 8080 : 443;

	let base64LinkIstls =
		'dmxlc3M6Ly8jdXVpZDQjQCNzZXJ2ZXIjOiNwb3J0Iz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9dGxzJnNuaT0jaG9zdE5hbWUjJmZwPWNocm9tZSZhbGxvd0luc2VjdXJlPTEmdHlwZT13cyZob3N0PSNob3N0TmFtZSMmcGF0aD0jcGF0aCM';
	let base64LinkNottls =
		'dmxlc3M6Ly8jdXVpZDQjQCNzZXJ2ZXIjOiNwb3J0Iz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9bm9uZSZmcD1jaHJvbWUmYWxsb3dJbnNlY3VyZT0xJnR5cGU9d3MmaG9zdD0jaG9zdE5hbWUjJnBhdGg9I3BhdGgj';
	let base64YamlsIstls =
		'LSB0eXBlOiB2bGVzcw0KICBuYW1lOiAjc2VydmVyIw0KICBzZXJ2ZXI6ICNzZXJ2ZXIjDQogIHBvcnQ6ICNwb3J0Iw0KICB1dWlkOiAjdXVpZDQjDQogIG5ldHdvcms6IHdzDQogIHRsczogdHJ1ZQ0KICB1ZHA6IGZhbHNlDQogIHNlcnZlcm5hbWU6ICNob3N0TmFtZSMNCiAgY2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUNCiAgd3Mtb3B0czoNCiAgICBwYXRoOiAiLz9lZD0yMDQ4Ig0KICAgIGhlYWRlcnM6DQogICAgICBob3N0OiAjaG9zdE5hbWUj';
	let base64YamlNottls =
		'LSB0eXBlOiB2bGVzcw0KICBuYW1lOiAjc2VydmVyIw0KICBzZXJ2ZXI6ICNzZXJ2ZXIjDQogIHBvcnQ6ICNwb3J0Iw0KICB1dWlkOiAjdXVpZDQjDQogIG5ldHdvcms6IHdzDQogIHRsczogZmFsc2UNCiAgdWRwOiBmYWxzZQ0KICBjbGllbnQtZmluZ2VycHJpbnQ6IGNocm9tZQ0KICB3cy1vcHRzOg0KICAgIHBhdGg6ICIvP2VkPTIwNDgiDQogICAgaGVhZGVyczoNCiAgICAgIGhvc3Q6ICNob3N0TmFtZSM';
	let base64JsonString =
		'ew0KICAib3V0Ym91bmRzIjogWw0KICAgIHsNCiAgICAgICJuZXR3b3JrIjogInRjcCIsDQogICAgICAic2VydmVyIjogIiNzZXJ2ZXIjIiwNCiAgICAgICJzZXJ2ZXJfcG9ydCI6ICNwb3J0IywNCiAgICAgICJ0YWciOiAiI3NlcnZlciMiLA0KICAgICAgInRscyI6IHsNCiAgICAgICAgImVuYWJsZWQiOiAjb25UbHMjLA0KICAgICAgICAiaW5zZWN1cmUiOiB0cnVlLA0KICAgICAgICAic2VydmVyX25hbWUiOiAiI0hvc3QjIiwNCiAgICAgICAgInV0bHMiOiB7DQogICAgICAgICAgImVuYWJsZWQiOiB0cnVlLA0KICAgICAgICAgICJmaW5nZXJwcmludCI6ICJjaHJvbWUiDQogICAgICAgIH0NCiAgICAgIH0sDQogICAgICAidHJhbnNwb3J0Ijogew0KICAgICAgICAiZWFybHlfZGF0YV9oZWFkZXJfbmFtZSI6ICJTZWMtV2ViU29ja2V0LVByb3RvY29sIiwNCiAgICAgICAgImhlYWRlcnMiOiB7DQogICAgICAgICAgIkhvc3QiOiAiI0hvc3QjIg0KICAgICAgICB9LA0KICAgICAgICAicGF0aCI6ICIjcGF0aCMiLA0KICAgICAgICAidHlwZSI6ICJ3cyINCiAgICAgIH0sDQogICAgICAidHlwZSI6ICJ2bGVzcyIsDQogICAgICAidXVpZCI6ICIjdXVpZDQjIg0KICAgIH0NCiAgXQ0KfQ';

	let onTls = hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')) ? false : true;
	let base64LinkString = hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')) ? base64LinkNottls : base64LinkIstls;
	let base64YamlString = hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')) ? base64YamlNottls : base64YamlsIstls;

	let replacements = {
		'#uuid4#': userID,
		'#server#': server,
		'#port#': port,
		'#hostName#': hostName,
		'#path#': '%2F%3Fed%3D2048',
	};
	let finallyLink =
		Object.entries(replacements).reduce((acc, [key, value]) => {
			return acc.replace(new RegExp(key, 'g'), value);
		}, base64ToUtf8(base64LinkString)) +
		'#' +
		encodeURIComponent(`${server}:${port}`);
	let finallyYaml = Object.entries(replacements).reduce((acc, [key, value]) => {
		return acc.replace(new RegExp(key, 'g'), value);
	}, base64ToUtf8(base64YamlString));

	// 要替换的字符串
	let replacementsSingbx = {
		'#server#': server,
		'#port#': port,
		'#uuid4#': userID,
		'#Host#': hostName,
		'#onTls#': onTls,
		'#path#': decodeURIComponent('%2F%3Fed%3D2048'),
	};
	let finallyJson = Object.entries(replacementsSingbx).reduce((acc, [key, value]) => {
		return acc.replace(new RegExp(key, 'g'), value);
	}, base64ToUtf8(base64JsonString));
	return `
################################################################
${base64ToUtf8('djJyYXk')}
---------------------------------------------------------------
${finallyLink}
---------------------------------------------------------------
################################################################
${base64ToUtf8('c2luZy1ib3g')}
---------------------------------------------------------------
${finallyJson}
---------------------------------------------------------------
################################################################
${base64ToUtf8('Y2xhc2gubWV0YShtaWhvbW8p')}
---------------------------------------------------------------
${finallyYaml}
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
	const cidrMatch = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
	if (!cidrMatch) return [];
	const baseIp = cidrMatch[1];
	const subnetMask = Number(cidrMatch[2]);
	const ipArray = baseIp.split('.').map(Number);
	const maskBits = 32 - subnetMask;
	const maxSubnetSize = Math.pow(2, maskBits) - 2;
	const baseIpNum = ipArray.reduce((sum, num, idx) => sum + (num << ((3 - idx) * 8)), 0);
	const ips = [];
	for (let i = 1; i <= maxSubnetSize; i++) {
		const ipNum = baseIpNum + i;
		const ip = [(ipNum >>> 24) & 255, (ipNum >>> 16) & 255, (ipNum >>> 8) & 255, ipNum & 255].join('.');
		ips.push(ip);
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
	const allIps = cidrList.map(generateAllIpsFromCidr).flat();
	const uniqueIps = new Set();
	while (uniqueIps.size < count && uniqueIps.size < allIps.length) {
		const randomIndex = Math.floor(Math.random() * allIps.length);
		uniqueIps.add(allIps[randomIndex]);
	}

	return [...uniqueIps];
}

/**
 * 将IPv4地址转换成数字表示形式。
 * @param {string} ip - IPv4地址，格式为xxx.xxx.xxx.xxx，其中xxx为0-255之间的整数。
 * @returns {number} - 返回对应IPv4地址的数字表示形式。
 */
function ipToNumber(ip) {
	return ip.split('.').reduce((acc, octet) => acc * 256 + parseInt(octet, 10), 0);
}

/**
 * 对IP地址数组进行排序(可以排序非IP地址的)
 * @param {string[]} ipAddresses - 包含IP地址的字符串数组。
 * @return {string[]} - 返回按IP地址数字值升序排序后的数组。
 */
function sortIpAddresses(ipAddresses) {
	return ipAddresses.sort((a, b) => {
		if (isValidIpAddress(a) && isValidIpAddress(b)) {
			return ipToNumber(a) - ipToNumber(b);
		} else if (!isValidIpAddress(a) && !isValidIpAddress(b)) {
			return a.localeCompare(b);
		} else {
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
	const parts = ip.split('.');
	return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && parseInt(part, 10) >= 0 && parseInt(part, 10) <= 255);
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
			return '';
		} else {
			return await response.text();
		}
	} catch (err) {
		console.error(`Failed to fetch ${URL} web conten: ${err.message}`);
		return '';
	}
}

/**
 *
 * @param {string} cidrParam - 从get请求链接中，获取cidr参数的cidr值(支持多个cidr传入，用逗号分割)
 * @returns {Array} - 返回cidrs范围内IP数组（IP一定不重复，且在cidrs数组里面cidr范围内，数量最多1000个，取决于cidr的范围）
 */
function getCidrParamAndGenerateIps(cidrParam) {
	let cidrs = [];
	let vessArray = [];
	if (cidrParam.includes(',')) {
		cidrs = cidrParam.split(',');
	} else {
		cidrs = [cidrParam];
	}
	const randomIps = randomIpsFromCidrList(cidrs, 1000);
	return randomIps;
}

/**
 * 遍历ipsArray数组，生成vless链接，返回vless链接的数组
 * @param {Array} ipsArray - 包含大量IP的数组
 * @param {string} hostName - sni、headers.host的地址
 * @param {string} port - 端口
 * @param {string} path - vless配置中的path
 * @param {string} userID - uuid4
 * @returns {Array} - 返回vless的数组
 */
function eachIpsArrayAndGeneratevess(ipsArray, hostName, portParam, path, userID) {
	let resultsArray = [];
	for (let i = 0; i < ipsArray.length; i++) {
		const ipaddr = ipsArray[i].trim();
		let randomHttpPortElement = getRandomElement(HTTP_WITH_PORTS);
		let randomHttpsPortElement = getRandomElement(HTTPS_WITH_PORTS);
		let port =
			([0, ...HTTPS_WITH_PORTS].includes(Number(portParam)) && hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY='))) ||
			([0, ...HTTP_WITH_PORTS].includes(Number(portParam)) && !hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')))
				? hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY='))
					? randomHttpPortElement
					: randomHttpsPortElement
				: portParam;
		let base64LinkIstls =
			'dmxlc3M6Ly8jdXVpZDQjQCNzZXJ2ZXIjOiNwb3J0Iz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9dGxzJnNuaT0jaG9zdE5hbWUjJmZwPWNocm9tZSZhbGxvd0luc2VjdXJlPTEmdHlwZT13cyZob3N0PSNob3N0TmFtZSMmcGF0aD0jcGF0aCM';
		let base64LinkNottls =
			'dmxlc3M6Ly8jdXVpZDQjQCNzZXJ2ZXIjOiNwb3J0Iz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9bm9uZSZmcD1jaHJvbWUmYWxsb3dJbnNlY3VyZT0xJnR5cGU9d3MmaG9zdD0jaG9zdE5hbWUjJnBhdGg9I3BhdGgj';

		let base64LinkString = hostName.includes(base64ToUtf8('d29ya2Vycy5kZXY=')) ? base64LinkNottls : base64LinkIstls;

		let replacements = {
			'#uuid4#': userID,
			'#server#': ipaddr,
			'#port#': port,
			'#hostName#': hostName,
			'#path#': path,
		};
		let finallyLink =
			Object.entries(replacements).reduce((acc, [key, value]) => {
				return acc.replace(new RegExp(key, 'g'), value);
			}, base64ToUtf8(base64LinkString)) +
			'#' +
			encodeURIComponent(`${ipaddr}:${port}`);

		if (finallyLink) {
			resultsArray.push(finallyLink);
		}
	}
	return resultsArray;
}

/**
 * 将一个数组分割成多个指定大小的子数组。
 * @param {Array} array - 需要分割的原始数组。
 * @param {number} chunkSize - 指定的子数组大小。
 * @returns {Array} 返回一个包含多个指定大小子数组的数组。
 */
function splitArray(array, chunkSize) {
	const chunks = [];
	let index = 0;
	while (index < array.length) {
		chunks.push(array.slice(index, index + chunkSize));
		index += chunkSize;
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
	const totalLength = array.length;
	const numChunks = Math.ceil(totalLength / maxChunkSize);
	const chunkSize = Math.ceil(totalLength / numChunks);
	return splitArray(array, chunkSize);
}

/**
 * 异步函数：使用提供的GitHub访问令牌(token)和其他参数，从指定的仓库中获取文件内容。
 *
 * @param {string} token - GitHub访问令牌，用于授权请求。
 * @param {string} owner - 仓库所有者的用户名。
 * @param {string} repo - 仓库名称。
 * @param {string} filePath - 要获取的文件路径。
 * @param {string} branch - 文件所在的分支名称。
 * @returns {Object} - 包含文件内容和内容类型的对象。如果请求失败，内容为空字符串。
 */
async function fetchGitHubFile(token, owner, repo, filePath, branch = 'main') {
	// 构建GitHub API请求URL
	const githubUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}?ref=${branch}`;

	try {
		// 发起GET请求到GitHub API，获取文件内容
		const response = await fetch(githubUrl, {
			method: 'GET',
			headers: {
				Authorization: `token ${token}`,
				Accept: 'application/vnd.github.v3.raw',
				'User-Agent': 'Cloudflare Worker',
			},
		});

		// 如果响应不成功，返回空字符串和文本类型
		if (!response.ok) {
			return {
				body: '',
				contentType: 'text/plain; charset=utf-8',
			};
		}

		// 从响应头中获取实际的内容类型，如果不存在则默认为二进制流类型
		const contentType = response.headers.get('Content-Type') || 'application/octet-stream';

		// 将响应内容转换为ArrayBuffer格式，以便于后续处理
		const body = await response.arrayBuffer();

		// 返回文件内容和内容类型
		return {
			body: body,
			contentType: contentType,
		};
	} catch (error) {
		// 如果请求过程中发生错误，返回空字符串和文本类型
		return {
			body: '',
			contentType: 'text/plain; charset=utf-8',
		};
	}
}

// 检查是否为"(子)域名、IPv4、[IPv6]、(子)域名:端口、IPv4:端口、[IPv6]:端口"中任意一个？
function isValidlandingAddress(ip) {
	var reg =
		/^(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?|(?:(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?|(?:\[[0-9a-fA-F:]+\])(?::\d{1,5})?)$/;
	return reg.test(ip);
}

// 解析path输入的landingAddress字符串，返回host和port的json值
function parselandingAddress(address) {
	// 匹配地址格式：(子)域名、IPv4、[IPv6]、(子)域名:端口、IPv4:端口、[IPv6]:端口
	const regex =
		/^(?:(?<domain>(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::(?<port>\d{1,5}))?|(?<ipv4>(?:\d{1,3}\.){3}\d{1,3})(?::(?<port_ipv4>\d{1,5}))?|(?<ipv6>\[[0-9a-fA-F:]+\])(?::(?<port_ipv6>\d{1,5}))?)$/;

	const match = address.match(regex);

	if (match) {
		let host = match.groups.domain || match.groups.ipv4 || match.groups.ipv6;
		let port = match.groups.port || match.groups.port_ipv4 || match.groups.port_ipv6 || undefined;

		return { host, port };
	} else {
		return { host: '', undefined };
	}
}

function getRandomElement(array) {
	const randomIndex = Math.floor(Math.random() * array.length);
	return array[randomIndex];
}

// 将base64加密的字符串转换为正经的字符串
function base64ToUtf8(base64Str) {
	let binary = atob(base64Str);
	let bytes = new Uint8Array([...binary].map((char) => char.charCodeAt(0)));
	let decoder = new TextDecoder();
	return decoder.decode(bytes);
}
