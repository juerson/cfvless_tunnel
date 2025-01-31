import { connect } from 'cloudflare:sockets';

let userID = '0648919d-8bf1-4d4c-8525-36cf487506ec';
let landingAddress = '';
let socks5Address = ''; // 格式: user:pass@host:port、:@host:port
let dohURL = 'https://dns.google.com/resolve';

const domainList = [
	'https://www.iq.com',
	'https://www.dell.com',
	'https://www.bilibili.com',
	'https://www.wix.com/',
	'https://landingsite.ai/',
	'https://www.pexels.com/',
	'https://www.revid.ai/',
];

let parsedSocks5Address = {};
let enableSocks = false;

export default {
	async fetch(request, env, ctx) {
		try {
			userID = env.UUID4 || userID;
			let landingAddr = env.LANDING_ADDRESS || landingAddress;
			let doh = env.DOH_URL || dohURL;
			let socks5Addr = env.SOCKS5 || socks5Address;
			// ————————————————————————————————————————————————————————————————————————————————
			if (!doh.startsWith('https://') && !doh.startsWith('http://')) {
				dohURL = 'https://' + doh;
			}
			if (landingAddr.includes(',')) {
				const arr = landingAddr.split(',');
				const randomIndex = Math.floor(Math.random() * arr.length);
				landingAddress = arr[randomIndex].trim();
			} else {
				landingAddress = landingAddr.trim();
			}
			if (socks5Addr) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Addr);
					enableSocks = true;
				} catch (err) {
					enableSocks = false;
				}
			}
			// ————————————————————————————————————————————————————————————————————————————————
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
					default:
						return new Response('This site can’t provide a secure connection', { status: 404 });
				}
			} else {
				const pathString = url.pathname;
				if (pathString.includes('/pyip=')) {
					const pathToLandingAddress = pathString.split('=')[1];
					if (isValidLandingAddress(pathToLandingAddress)) {
						landingAddress = pathToLandingAddress;
					}
				} else if (pathString.includes('/socks=')) {
					const pathToSocks = pathString.split('=')[1];
					const matchSocks = (socksAddress) => {
						const regex =
							/^(?:socks:\/\/)?(?:([a-zA-Z0-9._%+-]+):([a-zA-Z0-9._%+-]+)@)?([0-9]{1,3}(?:\.[0-9]{1,3}){3}:\d+|[a-zA-Z0-9.-]+:\d+)$/;
						const match = socksAddress.match(regex);
						if (match) {
							const [_, username, password, address] = match;
							return username && password ? `${username}:${password}@${address}` : `:@${address}`;
						}
						return '';
					};
					let socksAddress = matchSocks(pathToSocks);
					if (socksAddress.length !== 0) {
						parsedSocks5Address = socks5AddressParser(socksAddress);
						enableSocks = true;
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
	const [client, webSocket] = Object.values(new WebSocketPair());
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
						vlessVersion = new Uint8Array([0, 0]),
						isUDP,
					} = processVlessHeader(chunk, userID);
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
							// throw new Error('UDP proxy only enable for DNS which is port 53');
							return;
						}
					}
					const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
					const rawClientData = chunk.slice(rawDataIndex);
					if (isDns) {
						const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
						udpStreamWrite = write;
						udpStreamWrite(rawClientData);
						return;
					}
					handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
				},
				close() {
					log(`readableWebSocketStream is close`);
				},
				abort(reason) {
					log(`readableWebSocketStream is abort`, JSON.stringify(reason));
				},
			})
		)
		.catch((err) => {
			log('readableWebSocketStream pipeTo error', err);
		});
	return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
	async function connectAndWrite(address, port, socks = false) {
		const connectAddr = {
			hostname: address,
			port: port,
		};
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log) : connect(connectAddr);
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}
	async function retry() {
		if (enableSocks) {
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			let jsonAddr = landingAddressParse(landingAddress);
			tcpSocket = await connectAndWrite(jsonAddr.host || addressRemote, jsonAddr.port || portRemote);
		}
		tcpSocket.closed
			.catch((error) => {
				log('retry tcpSocket closed error', error);
			})
			.finally(() => {
				safeCloseWebSocket(webSocket);
			});
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	let tcpSocket = await connectAndWrite(addressRemote, portRemote);
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
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
				controller.error('webSocketServer has error', err);
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
			if (readableStreamCancel) return;
			log(`ReadableStream was canceled, due to ${reason}`);
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		},
	});

	return stream;
}

function processVlessHeader(vlessBuffer, userID) {
	if (vlessBuffer.byteLength < 24) {
		return { hasError: true, message: 'invalid data' };
	}
	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID) {
		isValidUser = true;
	}
	if (!isValidUser) {
		return { hasError: true, message: 'invalid user' };
	}

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
	if (command === 1) {
		// ignore
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
	const portRemote = new DataView(portBuffer).getUint16(0);
	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
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
		vlessVersion: version,
		isUDP,
	};
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false;
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {},
				async write(chunk, controller) {
					hasIncomingData = true;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error('webSocket.readyState is not open, maybe close');
					}
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
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
		log(`retry`);
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

function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError('Stringified UUID is invalid');
	}
	return uuid;
}

async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
	let isVlessHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {},
		transform(chunk, controller) {
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
						log(`doh success and dns message length is ${udpSize}`);
						if (isVlessHeaderSent) {
							webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
						} else {
							webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
							isVlessHeaderSent = true;
						}
					}
				},
			})
		)
		.catch((error) => {
			log('dns udp has error' + error);
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

	log('sent socks greeting');

	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	let res = (await reader.read()).value;
	if (res[0] !== 0x05) {
		log(`socks server version error: ${res[0]} expected: 5`);
		return;
	}
	if (res[1] === 0xff) {
		log('no acceptable methods');
		return;
	}
	if (res[1] === 0x02) {
		log('socks server needs auth');
		if (!username || !password) {
			log('please provide username/password');
			return;
		}
		const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
		await writer.write(authRequest);
		res = (await reader.read()).value;
		if (res[0] !== 0x01 || res[1] !== 0x00) {
			log('fail to auth socks server');
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
			log(`invild  addressType is ${addressType}`);
			return;
	}
	const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
	await writer.write(socksRequest);
	log('sent socks request');
	res = (await reader.read()).value;
	if (res[1] === 0x00) {
		log('socks connection opened');
	} else {
		log('fail to open socks connection');
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

// 检查是否为：(子)域名、IPv4、[IPv6]、(子)域名:端口、IPv4:端口、[IPv6]:端口
function isValidLandingAddress(ip) {
	var reg =
		/^(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?|(?:(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?|(?:\[[0-9a-fA-F:]+\])(?::\d{1,5})?)$/;
	return reg.test(ip);
}

// 解析HOST和PORT，字符串格式是否为：(子)域名、IPv4、[IPv6]、(子)域名:端口、IPv4:端口、[IPv6]:端口
function landingAddressParse(address) {
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
