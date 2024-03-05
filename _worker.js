// src/worker.js
import { connect } from "cloudflare:sockets";
var userID;
var proxyIP;
var socks5Address;
var showVless;
var domainList = [
  "https://www.iq.com",
  "https://www.wechat.com",
  "https://www.bilibili.com",
  "https://www.alibaba.com",
  "https://fmovies.llc/home",
  "https://www.visaitalia.com/",
  "https://www.techspot.com"
];
var parsedSocks5Address = {};
var enableSocks = false;
var worker_default = {
  /**
   * @param {import("@cloudflare/workers-types").Request} request
   * @param {{UUID: string, PROXYIP: string, SOCKS5: string, SHOW_VLESS: string}} env
   * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      userID = env.UUID;
      proxyIP = env.PROXYIP;
      socks5Address = env.SOCKS5;
      showVless = env.SHOW_VLESS;
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
          let e = err;
          console.log(e.toString());
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
          case `/${userID}`: {
            if (showVless === "on") {
              const vlessConfig = getVLESSConfig(userID, request.headers.get("Host"));
              return new Response(`${vlessConfig}`, {
                status: 200,
                headers: {
                  "Content-Type": "text/plain;charset=utf-8"
                }
              });
            } else {
              let uuid_page_messges = `\u60A8\u6CA1\u6709\u6743\u9650\u67E5\u770Bvless\u7684\u5206\u4EAB\u94FE\u63A5\u548C\u5BF9\u5E94\u7684clash-meta\u914D\u7F6E\u4FE1\u606F\uFF01\u8981\u67E5\u770Bvless\u7684\u5206\u4EAB\u94FE\u63A5\uFF0C\u9700\u8981\u5728Cloudflare\u7684"Workers \u548C Pages"\u540E\u53F0\uFF0C\u5C06\u8FD9\u4E2A\u9875\u9762\u7684\u5185\u5BB9\u663E\u793A\u51FA\u6765\uFF0C\u5177\u4F53\u6309\u4E0B\u9762\u7684\u6B65\u9AA4\u64CD\u4F5C\uFF1A

1\u3001\u5982\u679C\u4F7F\u7528Workers\u90E8\u7F72\u7684\uFF1A
  \u524D\u5F80\u60A8\u521B\u5EFA\u7684 Workers \u5E94\u7528\u7A0B\u5E8F\uFF0C\u5728\u91CC\u9762"\u8BBE\u7F6E >> \u53D8\u91CF >> \u73AF\u5883\u53D8\u91CF"\uFF0C\u5C06\u73AF\u5883\u53D8\u91CF SHOW_VLESS \u8BBE\u7F6E\u4E3A on \uFF0C
  \u4FDD\u5B58\u540E\uFF0C\u63A5\u7740\u5237\u65B0\u73B0\u5728\u8FD9\u4E2A\u7F51\u9875\uFF0C\u5C31\u80FD\u663E\u793Avless\u7684\u5206\u4EAB\u94FE\u63A5\u548Cclash-meta\u914D\u7F6E\u4FE1\u606F\u3002

2\u3001\u5982\u679C\u4F7F\u7528Pages\u90E8\u7F72\u7684\uFF1A
  \u524D\u5F80\u60A8\u521B\u5EFA\u7684 Pages \u5E94\u7528\u7A0B\u5E8F\uFF0C\u5728\u91CC\u9762"\u8BBE\u7F6E >> \u73AF\u5883\u53D8\u91CF >> \u5236\u4F5C(\u751F\u4EA7\u73AF\u5883)"\uFF0C\u5C06\u53D8\u91CF SHOW_VLESS \u8BBE\u7F6E\u4E3A on\uFF0C
  \u7136\u540E\u524D\u5F80"\u90E8\u7F72 >> \u6240\u6709\u90E8\u7F72 >> \u627E\u5230\u72B6\u6001\u680F\u4E2D\u65F6\u95F4\u6700\u8FD1\u54EA\u4E2A >> \u70B9\u53F3\u8FB9\u4E09\u4E2A\u70B9\u7684\u56FE\u6807 >> \u91CD\u8BD5\u90E8\u7F72"\uFF08\u5982\u679C\u662F\u672C\u5730\u4E0A\u4F20\u7684\uFF0C\u5C31"\u521B\u5EFA\u65B0\u90E8\u7F72"\uFF09\uFF0C
  \u518D\u6B21\u90E8\u7F72\uFF0C\u4FEE\u6539\u7684 SHOW_VLESS \u503C\u624D\u751F\u6548\uFF0C\u63A5\u7740\u5237\u65B0\u73B0\u5728\u8FD9\u4E2A\u7F51\u9875\uFF0C\u5C31\u80FD\u663E\u793Avless\u7684\u5206\u4EAB\u94FE\u63A5\u548Cclash-meta\u914D\u7F6E\u4FE1\u606F\u3002
`;
              return new Response(uuid_page_messges, {
                status: 200,
                headers: {
                  "Content-Type": "text/plain;charset=utf-8"
                }
              });
            }
          }
          default:
            return new Response("Not found", { status: 404 });
        }
      } else {
        return await vlessOverWSHandler(request);
      }
    } catch (err) {
      let e = err;
      return new Response(e.toString());
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
      portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
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
  return new Response(null, {
    status: 101,
    // @ts-ignore
    webSocket: client
  });
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
      webSocketServer.addEventListener(
        "error",
        (err) => {
          log("webSocketServer has error");
          controller.error(err);
        }
      );
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
    return {
      hasError: true,
      message: "invalid data"
    };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID2) {
    isValidUser = true;
  }
  if (!isValidUser) {
    return {
      hasError: true,
      message: "invalid user"
    };
  }
  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(
    vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
  )[0];
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
  const addressBuffer = new Uint8Array(
    vlessBuffer.slice(addressIndex, addressIndex + 1)
  );
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(
        vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      ).join(".");
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
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`
    };
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
      /**
       * 
       * @param {Uint8Array} chunk 
       * @param {*} controller 
       */
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
    console.error(
      `remoteSocketToWS has exception `,
      error.stack || error
    );
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
    const tcpSocket = connect({
      hostname: dnsServer,
      port: dnsPort
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
      }
    }));
  } catch (error) {
    console.error(
      `handleDNSQuery have exception, error: ${error.message}`
    );
  }
}
async function socks5Connect(addressType, addressRemote, portRemote, log) {
  const { username, password, hostname, port } = parsedSocks5Address;
  const socket = connect({
    hostname,
    port
  });
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
      DSTADDR = new Uint8Array(
        [1, ...addressRemote.split(".").map(Number)]
      );
      break;
    case 2:
      DSTADDR = new Uint8Array(
        [3, addressRemote.length, ...encoder.encode(addressRemote)]
      );
      break;
    case 3:
      DSTADDR = new Uint8Array(
        [4, ...addressRemote.split(":").flatMap((x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
      );
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
  return {
    username,
    password,
    hostname,
    port
  };
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
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
