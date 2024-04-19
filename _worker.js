// src/worker.js
import { connect } from "cloudflare:sockets";
var userID = "0648919d-8bf1-4d4c-8525-36cf487506ec";
var proxyList = ["cdn-all.xn--b6gac.eu.org", "cdn.xn--b6gac.eu.org", "cdn-b100.xn--b6gac.eu.org", "edgetunnel.anycast.eu.org", "cdn.anycast.eu.org"];
var proxyIP = proxyList[Math.floor(Math.random() * proxyList.length)];
var socks5Address = "";
var ipaddrURL = "https://ipupdate.baipiao.eu.org/";
var clash_template_url = "https://raw.githubusercontent.com/juerson/cfvless_tunnel/master/clash_template.yaml";
var configPassword = "";
var subPassword = "";
var domainList = [
  "https://www.iq.com",
  "https://www.dell.com",
  "https://www.bilibili.com",
  "https://www.alibaba.com",
  "https://fmovies.llc/home",
  "https://www.visaitalia.com/",
  "https://www.techspot.com"
];
var parsedSocks5Address = {};
var enableSocks = false;
var worker_default = {
  async fetch(request, env, ctx) {
    try {
      userID = env.UUID || userID;
      proxyIP = env.PROXYIP || proxyIP;
      socks5Address = env.SOCKS5 || socks5Address;
      configPassword = env.CONFIG_PASSWORD || configPassword;
      subPassword = env.SUB_PASSWORD || subPassword;
      if (proxyIP.includes(",")) {
        const arr = proxyIP.split(",");
        const randomIndex = Math.floor(Math.random() * arr.length);
        proxyIP = arr[randomIndex].trim();
      } else {
        proxyIP = proxyIP.trim();
      }
      if (socks5Address) {
        try {
          parsedSocks5Address = socks5AddressParser(socks5Address);
          enableSocks = true;
        } catch (err) {
          console.log(err.toString());
          enableSocks = false;
        }
      }
      const upgradeHeader = request.headers.get("Upgrade");
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const url = new URL(request.url);
        switch (url.pathname) {
          case "/":
            const randomDomain = domainList[Math.floor(Math.random() * domainList.length)];
            const redirectResponse = new Response("", {
              status: 301,
              headers: {
                "Location": randomDomain
              }
            });
            return redirectResponse;
          case `/config`: {
            let password2 = url.searchParams.get("pwd") || "";
            if (password2) {
              password2 = encodeURIComponent(password2);
              configPassword = encodeURIComponent(configPassword);
            }
            if (configPassword === password2) {
              const vlessConfig = getVLESSConfig(userID, request.headers.get("Host"));
              return new Response(`${vlessConfig}`, {
                status: 200,
                headers: {
                  "Content-Type": "text/plain;charset=utf-8"
                }
              });
            } else {
              return new Response("Not found", { status: 404 });
            }
          }
          case `/sub`:
            let password = url.searchParams.get("pwd") || "";
            let target = url.searchParams.get("target");
            let hostName = url.searchParams.get("hostName") || url.hostname;
            userID = url.searchParams.get("id") || userID;
            let portParam = url.searchParams.get("port");
            let pathParam = url.searchParams.get("path");
            let cidrParam = url.searchParams.get("cidr");
            if (password) {
              password = encodeURIComponent(password);
              subPassword = encodeURIComponent(subPassword);
            }
            if (!isValidUUID(userID)) {
              throw new Error("uuid is not valid");
            }
            let port = portParam || 443;
            let path = pathParam ? encodeURIComponent(pathParam) : "%2F%3Fed%3D2048";
            let ipsArray = [];
            if (!cidrParam && password === subPassword) {
              let ips_string = await fetchWebPageContent(ipaddrURL);
              let ips_Array = ips_string.trim().split(/\r\n|\n|\r/).map((ip) => ip.trim());
              ipsArray = sortIpAddresses(ips_Array);
            } else if (cidrParam && password === subPassword) {
              ipsArray = getCidrParamAndGenerateIps(cidrParam);
            } else {
              return new Response("Not found", { status: 404 });
            }
            if (target === "vless") {
              let page = url.searchParams.get("page") || 1;
              let maxNodeNumber = url.searchParams.get("maxNode") || 1e3;
              maxNodeNumber = maxNodeNumber > 0 && maxNodeNumber <= 5e3 ? maxNodeNumber : 1e3;
              let chunkedArray = splitArrayEvenly(ipsArray, maxNodeNumber);
              let totalPage = Math.ceil(ipsArray.length / maxNodeNumber);
              if (page > totalPage || page < 1) {
                return new Response("Not found", { status: 404 });
              }
              let ipsArrayChunked = chunkedArray[page - 1];
              let reusltArray = eachIpsArrayAndGenerateVless(ipsArrayChunked, hostName, port, path, userID);
              let vlessArrayStr = reusltArray.join("\n");
              let encoded = btoa(vlessArrayStr);
              return new Response(encoded, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
            } else if (target === "clash") {
              let page = url.searchParams.get("page") || 1;
              let maxNode = url.searchParams.get("maxNode") || 300;
              maxNode = maxNode > 0 && maxNode <= 1e3 ? maxNode : 300;
              let chunkedArray = splitArrayEvenly(ipsArray, maxNode);
              let totalPage = Math.ceil(ipsArray.length / maxNode);
              if (page > totalPage || page < 1) {
                return new Response("Not found", { status: 404 });
              }
              let clash_template = await fetchWebPageContent(clash_template_url);
              let ipsArrayChunked = chunkedArray[page - 1];
              let proxyies = [];
              let nodeNameArray = [];
              for (let i = 0; i < ipsArrayChunked.length; i++) {
                let ipaddr = ipsArrayChunked[i];
                let nodeName = `${ipaddr}:${port}`;
                let tls = hostName.includes("workers.dev") ? false : true;
                let sni = tls ? hostName : "";
                let clashConfig2 = `  - {"type":"vless","name":"${nodeName}","server":"${ipaddr}","port":${port},"uuid":"${userID}","network":"ws","tls":${tls},"udp":false,"sni":"${sni}","client-fingerprint":"chrome","ws-opts":{"path":"${path}","headers":{"host":"${hostName}"}}}`;
                proxyies.push(clashConfig2);
                nodeNameArray.push(nodeName);
              }
              let replaceProxyies = clash_template.replace(/  - {name: 01, server: 127.0.0.1, port: 80, type: ss, cipher: aes-128-gcm, password: a123456}/g, proxyies.join("\n"));
              let clashConfig = replaceProxyies.replace(/      - 01/g, nodeNameArray.map((ipWithPort) => `      - ${ipWithPort}`).join("\n")).replace(/dns-failed,/g, "");
              return new Response(clashConfig, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
            }
          default:
            return new Response("Not found", { status: 404 });
        }
      } else {
        return await vlessOverWSHandler(request);
      }
    } catch (err) {
      return new Response(err.toString());
    }
  }
};
async function vlessOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = {
    value: null
  };
  let isDns = false;
  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns) {
        return await handleDNSQuery(chunk, webSocket, null, log);
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
        addressRemote = "",
        rawDataIndex,
        vlessVersion = new Uint8Array([0, 0]),
        isUDP
      } = processVlessHeader(chunk, userID);
      address = addressRemote;
      portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "}`;
      if (hasError) {
        throw new Error(message);
        return;
      }
      if (isUDP) {
        if (portRemote === 53) {
          isDns = true;
        } else {
          throw new Error("UDP proxy only enable for DNS which is port 53");
          return;
        }
      }
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
    }
  })).catch((err) => {
    log("readableWebSocketStream pipeTo error", err);
  });
  return new Response(null, { status: 101, webSocket: client });
}
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
  async function connectAndWrite(address, port, socks = false) {
    const tcpSocket2 = socks ? await socks5Connect(addressType, address, port, log) : connect({
      hostname: address,
      port
    });
    remoteSocket.value = tcpSocket2;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  async function retry() {
    if (enableSocks) {
      tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
    } else {
      tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
    }
    tcpSocket.closed.catch((error) => {
      console.log("retry tcpSocket closed error", error);
    }).finally(() => {
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
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener(
        "close",
        () => {
          safeCloseWebSocket(webSocketServer);
          if (readableStreamCancel) {
            return;
          }
          controller.close();
        }
      );
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
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
    },
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  return stream;
}
function processVlessHeader(vlessBuffer, userID2) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: "invalid data" };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID2) {
    isValidUser = true;
  }
  if (!isValidUser) {
    return { hasError: true, message: "invalid user" };
  }
  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`
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
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
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
      addressValue = ipv6.join(":");
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
    isUDP
  };
}
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
  let remoteChunkCount = 0;
  let chunks = [];
  let vlessHeader = vlessResponseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable.pipeTo(
    new WritableStream({
      start() {
      },
      async write(chunk, controller) {
        hasIncomingData = true;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) {
          controller.error(
            "webSocket.readyState is not open, maybe close"
          );
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
      }
    })
  ).catch((error) => {
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
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}
var WS_READY_STATE_OPEN = 1;
var WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}
var byteToHex = [];
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
async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
  try {
    const dnsServer = "103.247.36.36";
    const dnsPort = 53;
    let vlessHeader = vlessResponseHeader;
    const tcpSocket = connect({ hostname: dnsServer, port: dnsPort });
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
      }
    }));
  } catch (error) {
    console.error(`handleDNSQuery have exception, error: ${error.message}`);
  }
}
async function socks5Connect(addressType, addressRemote, portRemote, log) {
  const { username, password, hostname, port } = parsedSocks5Address;
  const socket = connect({ hostname, port });
  const socksGreeting = new Uint8Array([5, 2, 0, 2]);
  const writer = socket.writable.getWriter();
  await writer.write(socksGreeting);
  log("sent socks greeting");
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  let res = (await reader.read()).value;
  if (res[0] !== 5) {
    log(`socks server version error: ${res[0]} expected: 5`);
    return;
  }
  if (res[1] === 255) {
    log("no acceptable methods");
    return;
  }
  if (res[1] === 2) {
    log("socks server needs auth");
    if (!username || !password) {
      log("please provide username/password");
      return;
    }
    const authRequest = new Uint8Array([
      1,
      username.length,
      ...encoder.encode(username),
      password.length,
      ...encoder.encode(password)
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 1 || res[1] !== 0) {
      log("fail to auth socks server");
      return;
    }
  }
  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array([1, ...addressRemote.split(".").map(Number)]);
      break;
    case 2:
      DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
      break;
    case 3:
      DSTADDR = new Uint8Array([4, ...addressRemote.split(":").flatMap((x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
      break;
    default:
      log(`invild  addressType is ${addressType}`);
      return;
  }
  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 255]);
  await writer.write(socksRequest);
  log("sent socks request");
  res = (await reader.read()).value;
  if (res[1] === 0) {
    log("socks connection opened");
  } else {
    log("fail to open socks connection");
    return;
  }
  writer.releaseLock();
  reader.releaseLock();
  return socket;
}
function socks5AddressParser(address) {
  let [latter, former] = address.split("@").reverse();
  let username, password, hostname, port;
  if (former) {
    const formers = former.split(":");
    if (formers.length !== 2) {
      throw new Error("Invalid SOCKS address format");
    }
    [username, password] = formers;
  }
  const latters = latter.split(":");
  port = Number(latters.pop());
  if (isNaN(port)) {
    throw new Error("Invalid SOCKS address format");
  }
  hostname = latters.join(":");
  const regex = /^\[.*\]$/;
  if (hostname.includes(":") && !regex.test(hostname)) {
    throw new Error("Invalid SOCKS address format");
  }
  return { username, password, hostname, port };
}
function getVLESSConfig(userID2, hostName) {
  const vlessMain = `vless://${userID2}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
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
  uuid: ${userID2}
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
function generateAllIpsFromCidr(cidr) {
  const cidrMatch = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!cidrMatch)
    return [];
  const baseIp = cidrMatch[1];
  const subnetMask = Number(cidrMatch[2]);
  const ipArray = baseIp.split(".").map(Number);
  const maskBits = 32 - subnetMask;
  const maxSubnetSize = Math.pow(2, maskBits) - 2;
  const baseIpNum = ipArray.reduce((sum, num, idx) => sum + (num << (3 - idx) * 8), 0);
  const ips = [];
  for (let i = 1; i <= maxSubnetSize; i++) {
    const ipNum = baseIpNum + i;
    const ip = [ipNum >>> 24 & 255, ipNum >>> 16 & 255, ipNum >>> 8 & 255, ipNum & 255].join(".");
    ips.push(ip);
  }
  return ips;
}
function randomIpsFromCidrList(cidrList, count) {
  const allIps = cidrList.map(generateAllIpsFromCidr).flat();
  const uniqueIps = /* @__PURE__ */ new Set();
  while (uniqueIps.size < count && uniqueIps.size < allIps.length) {
    const randomIndex = Math.floor(Math.random() * allIps.length);
    uniqueIps.add(allIps[randomIndex]);
  }
  return [...uniqueIps];
}
function ipToNumber(ip) {
  return ip.split(".").reduce((acc, octet) => acc * 256 + parseInt(octet, 10), 0);
}
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
function isValidIpAddress(ip) {
  const parts = ip.split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && parseInt(part, 10) >= 0 && parseInt(part, 10) <= 255);
}
async function fetchWebPageContent(URL2) {
  try {
    const response = await fetch(URL2);
    if (!response.ok) {
      throw new Error(`Failed to get: ${response.status}`);
      return "";
    } else {
      return await response.text();
    }
  } catch (err) {
    console.error(`Failed to fetch ${URL2} web conten: ${err.message}`);
    return "";
  }
}
function getCidrParamAndGenerateIps(cidrParam) {
  let cidrs = [];
  let vlessArray = [];
  if (cidrParam.includes(",")) {
    cidrs = cidrParam.split(",");
  } else {
    cidrs = [cidrParam];
  }
  const randomIps = randomIpsFromCidrList(cidrs, 1e3);
  return randomIps;
}
function eachIpsArrayAndGenerateVless(ipsArray, hostName, port, path, userID2) {
  let vlessArray = [];
  for (let i = 0; i < ipsArray.length; i++) {
    const ipaddr = ipsArray[i].trim();
    let vlessMain;
    if (ipaddr && hostName.includes("workers.dev")) {
      vlessMain = `vless://${userID2}@${ipaddr}:${port}?encryption=none&security=none&type=ws&host=${hostName}&path=${path}#${ipaddr}:${port}`;
    } else if (ipaddr) {
      vlessMain = `vless://${userID2}@${ipaddr}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${path}#${ipaddr}:${port}`;
    }
    if (vlessMain) {
      vlessArray.push(vlessMain);
    }
  }
  return vlessArray;
}
function splitArray(array, chunkSize) {
  const chunks = [];
  let index = 0;
  while (index < array.length) {
    chunks.push(array.slice(index, index + chunkSize));
    index += chunkSize;
  }
  return chunks;
}
function splitArrayEvenly(array, maxChunkSize) {
  const totalLength = array.length;
  const numChunks = Math.ceil(totalLength / maxChunkSize);
  const chunkSize = Math.ceil(totalLength / numChunks);
  return splitArray(array, chunkSize);
}
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
