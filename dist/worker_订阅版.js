// src/worker.js
import { connect } from "cloudflare:sockets";
var userID = "0648919d-8bf1-4d4c-8525-36cf487506ec";
var landingAddress = "";
var socks5Address = "";
var DEFAULT_GITHUB_TOKEN = "";
var DEFAULT_OWNER = "";
var DEFAULT_REPO = "";
var DEFAULT_BRANCH = "main";
var DEFAULT_FILE_PATH = "README.md";
var clashTemplateUrl = "https://raw.githubusercontent.com/juerson/cfvless_tunnel/refs/heads/master/clash_template.yaml";
var ipaddrURL = "https://raw.githubusercontent.com/juerson/cfvless_tunnel/refs/heads/master/ipaddr.txt";
var dohURL = "https://dns.google.com/resolve";
var configPassword = "";
var subPassword = "";
var HTTP_WITH_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
var HTTPS_WITH_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
var domainList = [
  "https://www.iq.com",
  "https://www.dell.com",
  "https://www.bilibili.com",
  "https://www.wix.com/",
  "https://landingsite.ai/",
  "https://vimeo.com/",
  "https://www.pexels.com/",
  "https://www.revid.ai/"
];
var parsedSocks5Address = {};
var enableSocks = false;
var worker_default = {
  async fetch(request, env, ctx) {
    try {
      userID = env.UUID4 || userID;
      landingAddress = env.LANDING_ADDRESS || landingAddress;
      socks5Address = env.SOCKS5 || socks5Address;
      configPassword = env.CONFIG_PASSWORD || configPassword;
      subPassword = env.SUB_PASSWORD || subPassword;
      dohURL = env.DOH_URL || dohURL;
      const GITHUB_TOKEN = env.GITHUB_TOKEN || DEFAULT_GITHUB_TOKEN;
      const OWNER = env.GITHUB_OWNER || DEFAULT_OWNER;
      const REPO = env.GITHUB_REPO || DEFAULT_REPO;
      const BRANCH = env.GITHUB_BRANCH || DEFAULT_BRANCH;
      const FILE_PATH = env.GITHUB_FILE_PATH || DEFAULT_FILE_PATH;
      if (landingAddress.includes(",")) {
        const arr = landingAddress.split(",");
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
          enableSocks = false;
        }
      }
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        switch (url.pathname) {
          case "/":
            const randomDomain = domainList[Math.floor(Math.random() * domainList.length)];
            const redirectResponse = new Response("", {
              status: 301,
              headers: {
                Location: randomDomain
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
              const baseConfig = getBaseConfig(userID, request.headers.get("Host"));
              return new Response(`${baseConfig}`, {
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
            let portParam = url.searchParams.get("port") || 0;
            let pathParam = url.searchParams.get("path");
            let cidrParam = url.searchParams.get("cidr");
            if (password) {
              password = encodeURIComponent(password);
              subPassword = encodeURIComponent(subPassword);
            }
            if (!isValidUUID(userID)) {
              throw new Error("uuid4 is not valid");
            }
            let path = pathParam ? encodeURIComponent(pathParam) : "%2F%3Fed%3D2048";
            let ipsArray = [];
            if (!cidrParam && password === subPassword) {
              let ips_string = "";
              try {
                const fileContent = await fetchGitHubFile(GITHUB_TOKEN, OWNER, REPO, FILE_PATH, BRANCH);
                const decoder = new TextDecoder("utf-8");
                ips_string = decoder.decode(fileContent.body);
              } catch (error) {
              }
              ips_string = ips_string !== "" ? ips_string : await fetchWebPageContent(ipaddrURL);
              let ips_Array = ips_string.trim().split(/\r\n|\n|\r/).map((ip) => ip.trim());
              ipsArray = sortIpAddresses(ips_Array);
            } else if (cidrParam && password === subPassword) {
              ipsArray = getCidrParamAndGenerateIps(cidrParam);
            } else {
              return new Response("Not found", { status: 404 });
            }
            let page = url.searchParams.get("page") || 1;
            if (target === "v2" || target === base64ToUtf8("djJyYXk")) {
              let maxNodeNumber = url.searchParams.get("maxNode") || 1e3;
              maxNodeNumber = maxNodeNumber > 0 && maxNodeNumber <= 5e3 ? maxNodeNumber : 1e3;
              let chunkedArray = splitArrayEvenly(ipsArray, maxNodeNumber);
              let totalPage = Math.ceil(ipsArray.length / maxNodeNumber);
              if (page > totalPage || page < 1) {
                return new Response("Not found", { status: 404 });
              }
              let ipsArrayChunked = chunkedArray[page - 1];
              let reusltArray = eachIpsArrayAndGeneratevess(ipsArrayChunked, hostName, portParam, path, userID);
              let vessArrayStr = reusltArray.join("\n");
              let encoded = btoa(vessArrayStr);
              return new Response(encoded, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
            } else if (target === base64ToUtf8("Y2xhc2g") || target === base64ToUtf8("bWlob21v")) {
              let maxNode = url.searchParams.get("maxNode") || 300;
              maxNode = maxNode > 0 && maxNode <= 1e3 ? maxNode : 300;
              let chunkedArray = splitArrayEvenly(ipsArray, maxNode);
              let totalPage = Math.ceil(ipsArray.length / maxNode);
              if (page > totalPage || page < 1) {
                return new Response("Not found", { status: 404 });
              }
              let clashTemplate = await fetchWebPageContent(clashTemplateUrl);
              let ipsArrayChunked = chunkedArray[page - 1];
              let proxyies = [];
              let nodeNameArray = [];
              const base64String = "eyJ0eXBlIjoidmxlc3MiLCJuYW1lIjoiIiwic2VydmVyIjoiIiwicG9ydCI6NDQzLCJ1dWlkIjoiI3V1aWQ0IyIsIm5ldHdvcmsiOiJ3cyIsInRscyI6dHJ1ZSwidWRwIjpmYWxzZSwic2VydmVybmFtZSI6IiIsImNsaWVudC1maW5nZXJwcmludCI6ImNocm9tZSIsIndzLW9wdHMiOnsicGF0aCI6IiNwYXRoIyIsImhlYWRlcnMiOnsiSG9zdCI6IiNIb3N0IyJ9fX0";
              const decodedString = base64ToUtf8(base64String);
              const uriDecodedString = decodeURIComponent(decodedString);
              for (let i = 0; i < ipsArrayChunked.length; i++) {
                let ipaddr = ipsArrayChunked[i];
                let randomHttpPortElement = getRandomElement(HTTP_WITH_PORTS);
                let randomHttpsPortElement = getRandomElement(HTTPS_WITH_PORTS);
                let port = [0, ...HTTPS_WITH_PORTS].includes(Number(portParam)) && hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) || [0, ...HTTP_WITH_PORTS].includes(Number(portParam)) && !hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? randomHttpPortElement : randomHttpsPortElement : portParam;
                let nodeName = `${ipaddr}:${port}`;
                const jsonObject = JSON.parse(uriDecodedString);
                jsonObject.name = nodeName;
                jsonObject.server = ipaddr;
                jsonObject.port = port;
                jsonObject.servername = hostName;
                let replacements = {
                  "#uuid4#": userID,
                  "#Host#": hostName,
                  "#path#": decodeURIComponent(path)
                };
                if (hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY="))) {
                  jsonObject.tls = false;
                  delete jsonObject.servername;
                }
                let modifiedResult = Object.entries(replacements).reduce((acc, [key, value]) => {
                  return acc.replace(new RegExp(key, "g"), value);
                }, `  - ${JSON.stringify(jsonObject)}`);
                proxyies.push(modifiedResult);
                nodeNameArray.push(nodeName);
              }
              let replaceProxyies = clashTemplate.replace(
                new RegExp(
                  atob(
                    "ICAtIHtuYW1lOiAwMSwgc2VydmVyOiAxMjcuMC4wLjEsIHBvcnQ6IDgwLCB0eXBlOiBzcywgY2lwaGVyOiBhZXMtMTI4LWdjbSwgcGFzc3dvcmQ6IGExMjM0NTZ9"
                  ),
                  "g"
                ),
                proxyies.join("\n")
              );
              let clashConfig = replaceProxyies.replace(
                new RegExp(atob("ICAgICAgLSAwMQ=="), "g"),
                nodeNameArray.map((ipWithPort) => `      - ${ipWithPort}`).join("\n")
              );
              return new Response(clashConfig, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
            } else if (target === base64ToUtf8("c2luZ2JveA")) {
              let maxNode = url.searchParams.get("maxNode") || 50;
              maxNode = maxNode > 0 && maxNode <= 100 ? maxNode : 50;
              let chunkedArray = splitArrayEvenly(ipsArray, maxNode);
              let totalPage = Math.ceil(ipsArray.length / maxNode);
              if (page > totalPage || page < 1) {
                return new Response("Not found", { status: 404 });
              }
              let ipsArrayChunked = chunkedArray[page - 1];
              let singbxnodes = [];
              let singbxtagname = [];
              for (let i = 0; i < ipsArrayChunked.length; i++) {
                let ipaddr = ipsArrayChunked[i];
                let randomHttpPortElement = getRandomElement(HTTP_WITH_PORTS);
                let randomHttpsPortElement = getRandomElement(HTTPS_WITH_PORTS);
                let port = [0, ...HTTPS_WITH_PORTS].includes(Number(portParam)) && hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) || [0, ...HTTP_WITH_PORTS].includes(Number(portParam)) && !hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? randomHttpPortElement : randomHttpsPortElement : portParam;
                let nodeName = `${ipaddr}:${port}`;
                let onTls = hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? false : true;
                let base64JsonString = "ICAgIHsNCiAgICAgICJuZXR3b3JrIjogInRjcCIsDQogICAgICAic2VydmVyIjogIiNzZXJ2ZXIjIiwNCiAgICAgICJzZXJ2ZXJfcG9ydCI6ICNwb3J0IywNCiAgICAgICJ0YWciOiAiI3RhZ25hbWUjIiwNCiAgICAgICJ0bHMiOiB7DQogICAgICAgICJlbmFibGVkIjogI29uVGxzIywNCiAgICAgICAgImluc2VjdXJlIjogdHJ1ZSwNCiAgICAgICAgInNlcnZlcl9uYW1lIjogIiNIb3N0IyIsDQogICAgICAgICJ1dGxzIjogew0KICAgICAgICAgICJlbmFibGVkIjogdHJ1ZSwNCiAgICAgICAgICAiZmluZ2VycHJpbnQiOiAiY2hyb21lIg0KICAgICAgICB9DQogICAgICB9LA0KICAgICAgInRyYW5zcG9ydCI6IHsNCiAgICAgICAgImVhcmx5X2RhdGFfaGVhZGVyX25hbWUiOiAiU2VjLVdlYlNvY2tldC1Qcm90b2NvbCIsDQogICAgICAgICJoZWFkZXJzIjogew0KICAgICAgICAgICJIb3N0IjogIiNIb3N0IyINCiAgICAgICAgfSwNCiAgICAgICAgInBhdGgiOiAiI3BhdGgjIiwNCiAgICAgICAgInR5cGUiOiAid3MiDQogICAgICB9LA0KICAgICAgInR5cGUiOiAidmxlc3MiLA0KICAgICAgInV1aWQiOiAiI3V1aWQ0IyINCiAgICB9";
                let replacements = {
                  "#server#": ipaddr,
                  "#port#": port,
                  "#uuid4#": userID,
                  "#Host#": hostName,
                  "#onTls#": onTls,
                  "#path#": decodeURIComponent(path),
                  "#tagname#": nodeName
                };
                let singbxNode = Object.entries(replacements).reduce((acc, [key, value]) => {
                  return acc.replace(new RegExp(key, "g"), value);
                }, base64ToUtf8(base64JsonString));
                singbxnodes.push(singbxNode);
                singbxtagname.push(nodeName);
              }
              let singbxconfig = base64ToUtf8("ew0KICAib3V0Ym91bmRzIjogWw0KI291dGJkcyMNCiAgXQ0KfQ").replace(
                "#outbds#",
                singbxnodes.join(",\n")
              );
              return new Response(singbxconfig, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
            }
          default:
            return new Response("Not found", { status: 404 });
        }
      } else {
        const pathString = url.pathname;
        if (pathString.includes("/pyip=")) {
          const pathpathLandingaddr = pathString.split("=")[1];
          if (isValidlandingAddress(pathpathLandingaddr)) {
            landingAddress = pathpathLandingaddr;
          }
        } else if (pathString.includes("/socks=")) {
          const pathSocks = pathString.split("=")[1];
          const matchSocks = (socksAddress2) => {
            const regex = /^(?:socks:\/\/)?(?:([a-zA-Z0-9._%+-]+):([a-zA-Z0-9._%+-]+)@)?([0-9]{1,3}(?:\.[0-9]{1,3}){3}:\d+|[a-zA-Z0-9.-]+:\d+)$/;
            const match = socksAddress2.match(regex);
            if (match) {
              const [_, username, password, address] = match;
              return username && password ? `${username}:${password}@${address}` : `:@${address}`;
            }
            return "";
          };
          let socksAddress = matchSocks(pathSocks);
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
  }
};
async function a1(request) {
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
  let udpStreamWrite = null;
  readableWebSocketStream.pipeTo(
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
          addressRemote = "",
          rawDataIndex,
          vessVersion = new Uint8Array([0, 0]),
          isUDP
        } = processvessHeader(chunk, userID);
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
      },
      abort(reason) {
      }
    })
  ).catch((err) => {
  });
  return new Response(null, { status: 101, webSocket: client });
}
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vessResponseHeader, log) {
  async function connectAndWrite(address, port, socks = false) {
    const tcpSocket2 = socks ? await socks5Connect(addressType, address, port, log) : connect({
      hostname: address,
      port
    });
    remoteSocket.value = tcpSocket2;
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  async function retry() {
    if (enableSocks) {
      tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
    } else {
      let pxAddressJSON = parselandingAddress(landingAddress);
      tcpSocket = await connectAndWrite(pxAddressJSON.host || addressRemote, pxAddressJSON.port || portRemote);
    }
    tcpSocket.closed.catch((error) => {
    }).finally(() => {
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
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
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
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  return stream;
}
function processvessHeader(vessBuffer, userID2) {
  if (vessBuffer.byteLength < 24) {
    return { hasError: true, message: "invalid data" };
  }
  const version = new Uint8Array(vessBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  if (stringify(new Uint8Array(vessBuffer.slice(1, 17))) === userID2) {
    isValidUser = true;
  }
  if (!isValidUser) {
    return { hasError: true, message: "invalid user" };
  }
  const optLength = new Uint8Array(vessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
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
  const portBuffer = vessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vessBuffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
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
    vessVersion: version,
    isUDP
  };
}
async function remoteSocketToWS(remoteSocket, webSocket, vessResponseHeader, retry, log) {
  let remoteChunkCount = 0;
  let chunks = [];
  let vessHeader = vessResponseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable.pipeTo(
    new WritableStream({
      start() {
      },
      async write(chunk, controller) {
        hasIncomingData = true;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) {
          controller.error("webSocket.readyState is not open, maybe close");
        }
        if (vessHeader) {
          webSocket.send(await new Blob([vessHeader, chunk]).arrayBuffer());
          vessHeader = null;
        } else {
          webSocket.send(chunk);
        }
      },
      close() {
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
function isValidUUID(uuid4) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid4);
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
  const uuid4 = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid4)) {
    throw TypeError("Stringified UUID4 is invalid");
  }
  return uuid4;
}
async function handleUDPOutBound(webSocket, vessResponseHeader, log) {
  let isvessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {
    },
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {
    }
  });
  transformStream.readable.pipeTo(
    new WritableStream({
      async write(chunk) {
        const resp = await fetch(dohURL, {
          method: "POST",
          headers: {
            "content-type": "application/dns-message"
          },
          body: chunk
        });
        const dnsQueryResult = await resp.arrayBuffer();
        const udpSize = dnsQueryResult.byteLength;
        const udpSizeBuffer = new Uint8Array([udpSize >> 8 & 255, udpSize & 255]);
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          if (isvessHeaderSent) {
            webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
          } else {
            webSocket.send(await new Blob([vessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            isvessHeaderSent = true;
          }
        }
      }
    })
  ).catch((error) => {
  });
  const writer = transformStream.writable.getWriter();
  return {
    write(chunk) {
      writer.write(chunk);
    }
  };
}
async function socks5Connect(addressType, addressRemote, portRemote, log) {
  const { username, password, hostname, port } = parsedSocks5Address;
  const socket = connect({ hostname, port });
  const socksGreeting = new Uint8Array([5, 2, 0, 2]);
  const writer = socket.writable.getWriter();
  await writer.write(socksGreeting);
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  let res = (await reader.read()).value;
  if (res[0] !== 5) {
    return;
  }
  if (res[1] === 255) {
    return;
  }
  if (res[1] === 2) {
    if (!username || !password) {
      return;
    }
    const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 1 || res[1] !== 0) {
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
      return;
  }
  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 255]);
  await writer.write(socksRequest);
  res = (await reader.read()).value;
  if (res[1] === 0) {
  } else {
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
function getBaseConfig(userID2, hostName) {
  let server = "www.visa.com.sg";
  let port = hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? 8080 : 443;
  let base64LinkIstls = "dmxlc3M6Ly8jdXVpZDQjQCNzZXJ2ZXIjOiNwb3J0Iz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9dGxzJnNuaT0jaG9zdE5hbWUjJmZwPWNocm9tZSZhbGxvd0luc2VjdXJlPTEmdHlwZT13cyZob3N0PSNob3N0TmFtZSMmcGF0aD0jcGF0aCM";
  let base64LinkNottls = "dmxlc3M6Ly8jdXVpZDQjQCNzZXJ2ZXIjOiNwb3J0Iz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9bm9uZSZmcD1jaHJvbWUmYWxsb3dJbnNlY3VyZT0xJnR5cGU9d3MmaG9zdD0jaG9zdE5hbWUjJnBhdGg9I3BhdGgj";
  let base64YamlsIstls = "LSB0eXBlOiB2bGVzcw0KICBuYW1lOiAjc2VydmVyIw0KICBzZXJ2ZXI6ICNzZXJ2ZXIjDQogIHBvcnQ6ICNwb3J0Iw0KICB1dWlkOiAjdXVpZDQjDQogIG5ldHdvcms6IHdzDQogIHRsczogdHJ1ZQ0KICB1ZHA6IGZhbHNlDQogIHNlcnZlcm5hbWU6ICNob3N0TmFtZSMNCiAgY2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUNCiAgd3Mtb3B0czoNCiAgICBwYXRoOiAiLz9lZD0yMDQ4Ig0KICAgIGhlYWRlcnM6DQogICAgICBob3N0OiAjaG9zdE5hbWUj";
  let base64YamlNottls = "LSB0eXBlOiB2bGVzcw0KICBuYW1lOiAjc2VydmVyIw0KICBzZXJ2ZXI6ICNzZXJ2ZXIjDQogIHBvcnQ6ICNwb3J0Iw0KICB1dWlkOiAjdXVpZDQjDQogIG5ldHdvcms6IHdzDQogIHRsczogZmFsc2UNCiAgdWRwOiBmYWxzZQ0KICBjbGllbnQtZmluZ2VycHJpbnQ6IGNocm9tZQ0KICB3cy1vcHRzOg0KICAgIHBhdGg6ICIvP2VkPTIwNDgiDQogICAgaGVhZGVyczoNCiAgICAgIGhvc3Q6ICNob3N0TmFtZSM";
  let base64JsonString = "ew0KICAib3V0Ym91bmRzIjogWw0KICAgIHsNCiAgICAgICJuZXR3b3JrIjogInRjcCIsDQogICAgICAic2VydmVyIjogIiNzZXJ2ZXIjIiwNCiAgICAgICJzZXJ2ZXJfcG9ydCI6ICNwb3J0IywNCiAgICAgICJ0YWciOiAiI3NlcnZlciMiLA0KICAgICAgInRscyI6IHsNCiAgICAgICAgImVuYWJsZWQiOiAjb25UbHMjLA0KICAgICAgICAiaW5zZWN1cmUiOiB0cnVlLA0KICAgICAgICAic2VydmVyX25hbWUiOiAiI0hvc3QjIiwNCiAgICAgICAgInV0bHMiOiB7DQogICAgICAgICAgImVuYWJsZWQiOiB0cnVlLA0KICAgICAgICAgICJmaW5nZXJwcmludCI6ICJjaHJvbWUiDQogICAgICAgIH0NCiAgICAgIH0sDQogICAgICAidHJhbnNwb3J0Ijogew0KICAgICAgICAiZWFybHlfZGF0YV9oZWFkZXJfbmFtZSI6ICJTZWMtV2ViU29ja2V0LVByb3RvY29sIiwNCiAgICAgICAgImhlYWRlcnMiOiB7DQogICAgICAgICAgIkhvc3QiOiAiI0hvc3QjIg0KICAgICAgICB9LA0KICAgICAgICAicGF0aCI6ICIjcGF0aCMiLA0KICAgICAgICAidHlwZSI6ICJ3cyINCiAgICAgIH0sDQogICAgICAidHlwZSI6ICJ2bGVzcyIsDQogICAgICAidXVpZCI6ICIjdXVpZDQjIg0KICAgIH0NCiAgXQ0KfQ";
  let onTls = hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? false : true;
  let base64LinkString = hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? base64LinkNottls : base64LinkIstls;
  let base64YamlString = hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? base64YamlNottls : base64YamlsIstls;
  let replacements = {
    "#uuid4#": userID2,
    "#server#": server,
    "#port#": port,
    "#hostName#": hostName,
    "#path#": "%2F%3Fed%3D2048"
  };
  let finallyLink = Object.entries(replacements).reduce((acc, [key, value]) => {
    return acc.replace(new RegExp(key, "g"), value);
  }, base64ToUtf8(base64LinkString)) + "#" + encodeURIComponent(`${server}:${port}`);
  let finallyYaml = Object.entries(replacements).reduce((acc, [key, value]) => {
    return acc.replace(new RegExp(key, "g"), value);
  }, base64ToUtf8(base64YamlString));
  let replacementsSingbx = {
    "#server#": server,
    "#port#": port,
    "#uuid4#": userID2,
    "#Host#": hostName,
    "#onTls#": onTls,
    "#path#": decodeURIComponent("%2F%3Fed%3D2048")
  };
  let finallyJson = Object.entries(replacementsSingbx).reduce((acc, [key, value]) => {
    return acc.replace(new RegExp(key, "g"), value);
  }, base64ToUtf8(base64JsonString));
  return `
################################################################
${base64ToUtf8("djJyYXk")}
---------------------------------------------------------------
${finallyLink}
---------------------------------------------------------------
################################################################
${base64ToUtf8("c2luZy1ib3g")}
---------------------------------------------------------------
${finallyJson}
---------------------------------------------------------------
################################################################
${base64ToUtf8("Y2xhc2gubWV0YShtaWhvbW8p")}
---------------------------------------------------------------
${finallyYaml}
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
  let vessArray = [];
  if (cidrParam.includes(",")) {
    cidrs = cidrParam.split(",");
  } else {
    cidrs = [cidrParam];
  }
  const randomIps = randomIpsFromCidrList(cidrs, 1e3);
  return randomIps;
}
function eachIpsArrayAndGeneratevess(ipsArray, hostName, portParam, path, userID2) {
  let resultsArray = [];
  for (let i = 0; i < ipsArray.length; i++) {
    const ipaddr = ipsArray[i].trim();
    let randomHttpPortElement = getRandomElement(HTTP_WITH_PORTS);
    let randomHttpsPortElement = getRandomElement(HTTPS_WITH_PORTS);
    let port = [0, ...HTTPS_WITH_PORTS].includes(Number(portParam)) && hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) || [0, ...HTTP_WITH_PORTS].includes(Number(portParam)) && !hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? randomHttpPortElement : randomHttpsPortElement : portParam;
    let base64LinkIstls = "dmxlc3M6Ly8jdXVpZDQjQCNzZXJ2ZXIjOiNwb3J0Iz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9dGxzJnNuaT0jaG9zdE5hbWUjJmZwPWNocm9tZSZhbGxvd0luc2VjdXJlPTEmdHlwZT13cyZob3N0PSNob3N0TmFtZSMmcGF0aD0jcGF0aCM";
    let base64LinkNottls = "dmxlc3M6Ly8jdXVpZDQjQCNzZXJ2ZXIjOiNwb3J0Iz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9bm9uZSZmcD1jaHJvbWUmYWxsb3dJbnNlY3VyZT0xJnR5cGU9d3MmaG9zdD0jaG9zdE5hbWUjJnBhdGg9I3BhdGgj";
    let base64LinkString = hostName.includes(base64ToUtf8("d29ya2Vycy5kZXY=")) ? base64LinkNottls : base64LinkIstls;
    let replacements = {
      "#uuid4#": userID2,
      "#server#": ipaddr,
      "#port#": port,
      "#hostName#": hostName,
      "#path#": path
    };
    let finallyLink = Object.entries(replacements).reduce((acc, [key, value]) => {
      return acc.replace(new RegExp(key, "g"), value);
    }, base64ToUtf8(base64LinkString)) + "#" + encodeURIComponent(`${ipaddr}:${port}`);
    if (finallyLink) {
      resultsArray.push(finallyLink);
    }
  }
  return resultsArray;
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
async function fetchGitHubFile(token, owner, repo, filePath, branch = "main") {
  const githubUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}?ref=${branch}`;
  try {
    const response = await fetch(githubUrl, {
      method: "GET",
      headers: {
        Authorization: `token ${token}`,
        Accept: "application/vnd.github.v3.raw",
        "User-Agent": "Cloudflare Worker"
      }
    });
    if (!response.ok) {
      return {
        body: "",
        contentType: "text/plain; charset=utf-8"
      };
    }
    const contentType = response.headers.get("Content-Type") || "application/octet-stream";
    const body = await response.arrayBuffer();
    return {
      body,
      contentType
    };
  } catch (error) {
    return {
      body: "",
      contentType: "text/plain; charset=utf-8"
    };
  }
}
function isValidlandingAddress(ip) {
  var reg = /^(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?|(?:(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?|(?:\[[0-9a-fA-F:]+\])(?::\d{1,5})?)$/;
  return reg.test(ip);
}
function parselandingAddress(address) {
  const regex = /^(?:(?<domain>(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::(?<port>\d{1,5}))?|(?<ipv4>(?:\d{1,3}\.){3}\d{1,3})(?::(?<port_ipv4>\d{1,5}))?|(?<ipv6>\[[0-9a-fA-F:]+\])(?::(?<port_ipv6>\d{1,5}))?)$/;
  const match = address.match(regex);
  if (match) {
    let host = match.groups.domain || match.groups.ipv4 || match.groups.ipv6;
    let port = match.groups.port || match.groups.port_ipv4 || match.groups.port_ipv6 || void 0;
    return { host, port };
  } else {
    return { host: "", undefined: void 0 };
  }
}
function getRandomElement(array) {
  const randomIndex = Math.floor(Math.random() * array.length);
  return array[randomIndex];
}
function base64ToUtf8(base64Str) {
  let binary = atob(base64Str);
  let bytes = new Uint8Array([...binary].map((char) => char.charCodeAt(0)));
  let decoder = new TextDecoder();
  return decoder.decode(bytes);
}
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
