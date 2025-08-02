import { base64Encode, base64Decode } from './base64.js';

// chrome、firefox、edge、safari、ios、android、random、randomized
const base64Fp = ["Y2hyb21l", "ZmlyZWZveA==", "ZWRnZQ==", "c2FmYXJp", "aW9z", "YW5kcm9pZA==", "cmFuZG9t", "cmFuZG9taXplZA=="];
const HTTP_WITH_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
const HTTPS_WITH_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
function getRandomElement(array) {
	const randomIndex = Math.floor(Math.random() * array.length);
	return array[randomIndex];
}

function markdownToHtml(md) {
	return md
		.replace(/^# (.*$)/gim, '<h1>$1</h1>')
		.replace(/^## (.*$)/gim, '<h2>$1</h2>')
		.replace(/^### (.*$)/gim, '<h3>$1</h3>')
		.replace(/`{3}([\s\S]*?)`{3}/gim, '<pre><code>$1</code></pre>')
		.replace(/`([^`]+)`/gim, '<code>$1</code>')
		.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
		.replace(/\*(.*?)\*/gim, '<em>$1</em>')
		.replace(/\n$/gim, '<br />');
}

export function getBaseConfig(subParameter, hostName, nodePath = "/") {
	let { uuid, password, onSs } = subParameter;
	let addr = "www.visa.com";
	let path = nodePath;
	let plugin = (isWorkersDevDomain) => {
		return encodeURIComponent([`${atob("djJyYXktcGx1Z2lu")}`, ...(isWorkersDevDomain ? [] : ["tls"]), "mux=0", "mode=websocket", `path=${path}`, `host=${hostName}`].join(";"));
	};
	let params = [
		{
			"tls": "none",
			"port": getRandomElement(HTTP_WITH_PORTS),
			"plugin": plugin(true),
			"randomfp": atob(getRandomElement(base64Fp))
		},
		{
			"tls": "tls",
			"port": getRandomElement(HTTPS_WITH_PORTS),
			"plugin": plugin(false),
			"randomfp": atob(getRandomElement(base64Fp))
		}
	];

	// 分享链接
	let linkArray = [];
	for (let param of params) {
		let tls = param.tls;
		let plugin = param.plugin;
		let randomfp = param.randomfp;
		let serverAddr = `${addr}:${param.port}`;
		let remark = encodeURIComponent(`cfwks-${serverAddr}`);
		let linkArr = [
			`${atob("dmxlc3M6Ly8=")}${uuid}@${serverAddr}?${atob("ZW5jcnlwdGlvbj1ub25l")}&security=${tls}&fp=${randomfp}&${atob("YWxsb3dJbnNlY3VyZT0xJnR5cGU9d3M=")}&host=${hostName}&path=${encodeURIComponent(path)}#${remark}`,
			`${atob("dHJvamFuOi8v")}${password}@${serverAddr}?security=${tls}&fp=${randomfp}&${atob("YWxsb3dJbnNlY3VyZT0xJnR5cGU9d3M=")}&host=${hostName}&path=${encodeURIComponent(path)}#${remark}`,
			...(onSs ? [`${atob("c3M6Ly8=")}bm9uZTpub25l@${serverAddr}?plugin=${plugin}#${remark}`] : []),
		];
		linkArray.push(linkArr);
	}
	// singbox
	let jsonArr = [
		"ICAgIHsgDQogICAgICAidHlwZSI6ICJ2bGVzcyIsDQogICAgICAidGFnIjogIiNyZW1hcmtzIyIsDQogICAgICAic2VydmVyIjogIiNzZXJ2ZXIjIiwNCiAgICAgICJzZXJ2ZXJfcG9ydCI6ICNwb3J0IywNCiAgICAgICJ1dWlkIjogIiN1dWlkNCMiLA0KICAgICAgIm5ldHdvcmsiOiAidGNwIiwNCiAgICAgICJ0bHMiOiB7DQogICAgICAgICJlbmFibGVkIjogI3RscyMsDQogICAgICAgICJpbnNlY3VyZSI6IHRydWUsDQogICAgICAgICJzZXJ2ZXJfbmFtZSI6ICIjaG9zdE5hbWUjIiwNCiAgICAgICAgInV0bHMiOiB7DQogICAgICAgICAgImVuYWJsZWQiOiB0cnVlLA0KICAgICAgICAgICJmaW5nZXJwcmludCI6ICIjZnAjIg0KICAgICAgICB9DQogICAgICB9LA0KICAgICAgInRyYW5zcG9ydCI6IHsNCiAgICAgICAgInR5cGUiOiAid3MiLA0KICAgICAgICAicGF0aCI6ICIjcGF0aCMiLA0KICAgICAgICAiaGVhZGVycyI6IHsNCiAgICAgICAgICAiSG9zdCI6ICIjaG9zdE5hbWUjIg0KICAgICAgICB9DQogICAgICB9DQogICAgfQ",
		"ICAgIHsNCiAgICAgICJ0eXBlIjogInRyb2phbiIsDQogICAgICAidGFnIjogIiNyZW1hcmtzIyIsDQogICAgICAic2VydmVyIjogIiNzZXJ2ZXIjIiwNCiAgICAgICJzZXJ2ZXJfcG9ydCI6ICNwb3J0IywNCiAgICAgICJwYXNzd29yZCI6ICIjcGFzc3dvcmQjIiwNCiAgICAgICJuZXR3b3JrIjogInRjcCIsDQogICAgICAidGxzIjogew0KICAgICAgICAiZW5hYmxlZCI6ICN0bHMjLA0KICAgICAgICAiaW5zZWN1cmUiOiB0cnVlLA0KICAgICAgICAic2VydmVyX25hbWUiOiAiI2hvc3ROYW1lIyIsDQogICAgICAgICJ1dGxzIjogew0KICAgICAgICAgICJlbmFibGVkIjogdHJ1ZSwNCiAgICAgICAgICAiZmluZ2VycHJpbnQiOiAiI2ZwIyINCiAgICAgICAgfQ0KICAgICAgfSwNCiAgICAgICJ0cmFuc3BvcnQiOiB7DQogICAgICAgICJ0eXBlIjogIndzIiwNCiAgICAgICAgInBhdGgiOiAiI3BhdGgjIiwNCiAgICAgICAgImhlYWRlcnMiOiB7DQogICAgICAgICAgIkhvc3QiOiAiI2hvc3ROYW1lIyINCiAgICAgICAgfQ0KICAgICAgfQ0KICAgIH0",
		...(onSs ? ["ICAgIHsNCiAgICAgICJ0eXBlIjogInNoYWRvd3NvY2tzIiwNCiAgICAgICJ0YWciOiAiI3JlbWFya3MjIiwNCiAgICAgICJzZXJ2ZXIiOiAiI3NlcnZlciMiLA0KICAgICAgInNlcnZlcl9wb3J0IjogI3BvcnQjLA0KICAgICAgIm1ldGhvZCI6ICJub25lIiwNCiAgICAgICJwYXNzd29yZCI6ICJub25lIiwNCiAgICAgICJwbHVnaW4iOiAidjJyYXktcGx1Z2luIiwNCiAgICAgICJwbHVnaW5fb3B0cyI6ICIjdGxzdHIjbXV4PTA7bW9kZT13ZWJzb2NrZXQ7cGF0aD0jcGF0aCM7aG9zdD0jaG9zdE5hbWUjIg0KICAgIH0"] : []),
	];
	// clash/mihomo
	let yamlArr = [
		"cHJveGllczoKICAtIHR5cGU6IHZsZXNzCiAgICBuYW1lOiAnI3JlbWFya3MjJwogICAgc2VydmVyOiAnI3NlcnZlciMnCiAgICBwb3J0OiAjcG9ydCMKICAgIHV1aWQ6ICcjdXVpZDQjJwogICAgbmV0d29yazogd3MKICAgIHRsczogI3RscyMKICAgIHVkcDogZmFsc2UKICAgIHNlcnZlcm5hbWU6ICcjaG9zdE5hbWUjJwogICAgY2xpZW50LWZpbmdlcnByaW50OiAnI2ZwIycKICAgIHNraXAtY2VydC12ZXJpZnk6IHRydWUKICAgIHdzLW9wdHM6CiAgICAgIHBhdGg6ICcjcGF0aCMnCiAgICAgIGhlYWRlcnM6CiAgICAgICAgSG9zdDogJyNob3N0TmFtZSMnCiAgLSB0eXBlOiB0cm9qYW4KICAgIG5hbWU6ICcjcmVtYXJrcyMnCiAgICBzZXJ2ZXI6ICcjc2VydmVyIycKICAgIHBvcnQ6ICNwb3J0IwogICAgcGFzc3dvcmQ6ICcjcGFzc3dvcmQjJwogICAgbmV0d29yazogd3MKICAgIHVkcDogZmFsc2UKICAgIHNuaTogJyNob3N0TmFtZSMnCiAgICBjbGllbnQtZmluZ2VycHJpbnQ6ICcjZnAjJwogICAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQogICAgd3Mtb3B0czoKICAgICAgcGF0aDogJyNwYXRoIycKICAgICAgaGVhZGVyczoKICAgICAgICBIb3N0OiAnI2hvc3ROYW1lIyc",
		...(onSs ? ["ICAtIHR5cGU6IHNzCiAgICBuYW1lOiAnI3JlbWFya3MjJwogICAgc2VydmVyOiAnI3NlcnZlciMnCiAgICBwb3J0OiAjcG9ydCMKICAgIGNpcGhlcjogbm9uZQogICAgcGFzc3dvcmQ6IG5vbmUKICAgIHVkcDogZmFsc2UKICAgIHBsdWdpbjogdjJyYXktcGx1Z2luCiAgICBwbHVnaW4tb3B0czoKICAgICAgbW9kZTogd2Vic29ja2V0CiAgICAgIHRsczogI3RscyMKICAgICAgaG9zdDogJyNob3N0TmFtZSMnCiAgICAgIHBhdGg6ICcjcGF0aCMnCiAgICAgIG11eDogZmFsc2U"] : []),
	]

	let replacements = {
		'#remarks#': "cfwks-ws-tls",
		'#server#': addr,
		'#port#': getRandomElement(HTTPS_WITH_PORTS),
		'#uuid4#': uuid,
		'#password#': password,
		'#tls#': true,
		'#hostName#': hostName,
		'#path#': path,
		'#fp#': atob(getRandomElement(base64Fp)),
		'#tlstr#': "tls;"
	};
	let regex = new RegExp(Object.keys(replacements).join('|'), 'g');

	// singbox
	let jsonArray = [];
	jsonArr.forEach((ele) => {
		let objStr = base64Decode(ele).replace(regex, (match) => replacements[match]);
		const obj = JSON.parse(objStr);
		jsonArray.push(obj);
	});

	// clash
	let yamlArray = [];
	yamlArr.forEach((ele) => {
		let pValue = base64Decode(ele).replace(regex, (match) => replacements[match]);
		yamlArray.push(pValue);
	})
	let onS5ray = onSs ? `\n### 3、${base64Decode("c3PljY/orq7lnKh2MnJheU4vdjJyYXlOR+S4reS9v+eUqA==")}
\`\`\`${base64Decode("5Yir5ZCNKHJlbWFyayk6")}            cfwks-ss
${base64Decode("5Zyw5Z2AKGFkZHJlc3MpOg==")}           ${addr}
${base64Decode("56uv5Y+jKHBvcnQpOg==")}              ${params[1].port}
${base64Decode("5a+G56CBKHBhc3N3b3JkKTo=")}          0
${base64Decode("5Yqg5a+G5pa55byPKGVuY3J5cHRpb24pOg==")}    none

${base64Decode("5bqV5bGC5Lyg6L6T5pa55byPKHRyYW5zcG9ydCk=")}
${base64Decode("5Lyg6L6T5Y2P6K6uKG5ldHdvcmspOg==")}        ws
${base64Decode("5Lyq6KOF5Z+f5ZCNKGhvc3QpOg==")}           ${hostName}
${base64Decode("6Lev5b6EKHBhdGgpOg==")}               ${path}

${base64Decode("5Lyg6L6T5bGC5a6J5YWoKFRMUyk6")}          tls
\`\`\`` : "";

	let markdown = `## 一、${base64Decode("5YiG5Lqr6ZO+5o6l")}
### 1、${base64Decode("V2Vic29ja2V0ICsgTlRMUw==")}
\`\`\`${linkArray[0].join("\n")}\`\`\`
### 2、${base64Decode("V2Vic29ja2V0ICsgVExT")}
\`\`\`${linkArray[1].join("\n")}\`\`\`${onS5ray}
## 二、${base64Decode("566A5piTIHNpbmctYm94IOmFjee9rg==")}
\`\`\`${JSON.stringify({ "outbounds": jsonArray }, null, 2)}\`\`\`
## 三、${base64Decode("566A5piTIGNsYXNoL21paG9tbyDphY3nva4=")}
\`\`\`${yamlArray.join("\n")}\`\`\``;
	let content = markdownToHtml(markdown);

	let htmlMainTemplate = "PCFET0NUWVBFIGh0bWw+DQo8aHRtbD4NCg0KPGhlYWQ+DQoJPG1ldGEgY2hhcnNldD0idXRmLTgiPg0KCTxzdHlsZT4NCgkJaHRtbCwNCgkJYm9keSB7DQoJCQltYXJnaW46IDA7DQoJCQlwYWRkaW5nOiAwOw0KCQkJZm9udC1mYW1pbHk6IHN5c3RlbS11aSwgc2Fucy1zZXJpZjsNCgkJCWJhY2tncm91bmQ6ICNmMGYyZjU7DQoJCQlkaXNwbGF5OiBmbGV4Ow0KCQkJanVzdGlmeS1jb250ZW50OiBjZW50ZXI7DQoJCQlhbGlnbi1pdGVtczogY2VudGVyOw0KCQl9DQoNCgkJLmJveCB7DQoJCQliYWNrZ3JvdW5kOiB3aGl0ZTsNCgkJCW1heC13aWR0aDogMTIwMHB4Ow0KCQkJd2lkdGg6IDkwJTsNCgkJCXBhZGRpbmc6IDJyZW07DQoJCQlib3JkZXItcmFkaXVzOiAxMnB4Ow0KCQkJYm94LXNoYWRvdzogMCA0cHggMjBweCByZ2JhKDAsIDAsIDAsIDAuMSk7DQoJCX0NCg0KCQloMSwNCgkJaDIsDQoJCWgzIHsNCgkJCW1hcmdpbi10b3A6IDA7DQoJCX0NCg0KCQlwcmUgew0KCQkJYmFja2dyb3VuZDogI2VlZTsNCgkJCXBhZGRpbmc6IDFlbTsNCgkJCW92ZXJmbG93LXg6IGF1dG87DQoJCQlib3JkZXItcmFkaXVzOiA2cHg7DQoJCX0NCg0KCQljb2RlIHsNCgkJCWZvbnQtZmFtaWx5OiB1aS1tb25vc3BhY2UsIG1vbm9zcGFjZTsNCgkJfQ0KCTwvc3R5bGU+DQo8L2hlYWQ+DQoNCjxib2R5Pg0KCTxkaXYgY2xhc3M9ImJveCI+DQoJCSR7aHRtbH0NCgk8L2Rpdj4NCjwvYm9keT4NCg0KPC9odG1sPg0K"
	return base64Decode(htmlMainTemplate).replace("${html}", content);
}

export function buildLinks(ipsArray, subParameter, hostName, nodePath = "/", defaultPort = 0) {
	let path = nodePath;
	let isWorkersDevDomain = hostName.endsWith(atob("LndvcmtlcnMuZGV2"));
	let tls = isWorkersDevDomain ? "none" : "tls";
	let ports = isWorkersDevDomain ? HTTP_WITH_PORTS : HTTPS_WITH_PORTS;
	let plugin = encodeURIComponent([`${atob("djJyYXktcGx1Z2lu")}`, ...(isWorkersDevDomain ? [] : ["tls"]), "mux=0", "mode=websocket", `path=${path}`, `host=${hostName}`].join(";"));
	let { uuid, password, onSs } = subParameter;

	let linkArray = [];
	for (let addr of ipsArray) {
		if (!addr) continue;
		let port = (defaultPort !== 0) ? defaultPort : getRandomElement(ports);
		let serverAddr = `${addr}:${port}`;
		let remark = encodeURIComponent(`cfwks-${serverAddr}`);
		let randomfp = atob(getRandomElement(base64Fp));
		let linkArr = [
			`${atob("dmxlc3M6Ly8=")}${uuid}@${serverAddr}?${atob("ZW5jcnlwdGlvbj1ub25l")}&security=${tls}&fp=${randomfp}&${atob("YWxsb3dJbnNlY3VyZT0xJnR5cGU9d3M=")}&host=${hostName}&path=${encodeURIComponent(path)}#${remark}`,
			`${atob("dHJvamFuOi8v")}${password}@${serverAddr}?security=${tls}&fp=${randomfp}&${atob("YWxsb3dJbnNlY3VyZT0xJnR5cGU9d3M=")}&host=${hostName}&path=${encodeURIComponent(path)}#${remark}`,
			...(onSs ? [`${atob("c3M6Ly8=")}bm9uZTpub25l@${serverAddr}?plugin=${plugin}#${remark}`] : []),
		];
		linkArray.push(getRandomElement(linkArr));
	}

	return base64Encode(linkArray.join('\n'));
}

export function buildJsons(ipsArray, subParameter, hostName, nodePath = "/", defaultPort = 0) {
	let isWorkersDevDomain = hostName.endsWith(atob("LndvcmtlcnMuZGV2"));
	let ports = isWorkersDevDomain ? HTTP_WITH_PORTS : HTTPS_WITH_PORTS;
	let { uuid, password, onSs } = subParameter;
	let path = nodePath;
	let jsonArr = [
		"ICAgIHsgDQogICAgICAidHlwZSI6ICJ2bGVzcyIsDQogICAgICAidGFnIjogIiNyZW1hcmtzIyIsDQogICAgICAic2VydmVyIjogIiNzZXJ2ZXIjIiwNCiAgICAgICJzZXJ2ZXJfcG9ydCI6ICNwb3J0IywNCiAgICAgICJ1dWlkIjogIiN1dWlkNCMiLA0KICAgICAgIm5ldHdvcmsiOiAidGNwIiwNCiAgICAgICJ0bHMiOiB7DQogICAgICAgICJlbmFibGVkIjogI3RscyMsDQogICAgICAgICJpbnNlY3VyZSI6IHRydWUsDQogICAgICAgICJzZXJ2ZXJfbmFtZSI6ICIjaG9zdE5hbWUjIiwNCiAgICAgICAgInV0bHMiOiB7DQogICAgICAgICAgImVuYWJsZWQiOiB0cnVlLA0KICAgICAgICAgICJmaW5nZXJwcmludCI6ICIjZnAjIg0KICAgICAgICB9DQogICAgICB9LA0KICAgICAgInRyYW5zcG9ydCI6IHsNCiAgICAgICAgInR5cGUiOiAid3MiLA0KICAgICAgICAicGF0aCI6ICIjcGF0aCMiLA0KICAgICAgICAiaGVhZGVycyI6IHsNCiAgICAgICAgICAiSG9zdCI6ICIjaG9zdE5hbWUjIg0KICAgICAgICB9DQogICAgICB9DQogICAgfQ",
		"ICAgIHsNCiAgICAgICJ0eXBlIjogInRyb2phbiIsDQogICAgICAidGFnIjogIiNyZW1hcmtzIyIsDQogICAgICAic2VydmVyIjogIiNzZXJ2ZXIjIiwNCiAgICAgICJzZXJ2ZXJfcG9ydCI6ICNwb3J0IywNCiAgICAgICJwYXNzd29yZCI6ICIjcGFzc3dvcmQjIiwNCiAgICAgICJuZXR3b3JrIjogInRjcCIsDQogICAgICAidGxzIjogew0KICAgICAgICAiZW5hYmxlZCI6ICN0bHMjLA0KICAgICAgICAiaW5zZWN1cmUiOiB0cnVlLA0KICAgICAgICAic2VydmVyX25hbWUiOiAiI2hvc3ROYW1lIyIsDQogICAgICAgICJ1dGxzIjogew0KICAgICAgICAgICJlbmFibGVkIjogdHJ1ZSwNCiAgICAgICAgICAiZmluZ2VycHJpbnQiOiAiI2ZwIyINCiAgICAgICAgfQ0KICAgICAgfSwNCiAgICAgICJ0cmFuc3BvcnQiOiB7DQogICAgICAgICJ0eXBlIjogIndzIiwNCiAgICAgICAgInBhdGgiOiAiI3BhdGgjIiwNCiAgICAgICAgImhlYWRlcnMiOiB7DQogICAgICAgICAgIkhvc3QiOiAiI2hvc3ROYW1lIyINCiAgICAgICAgfQ0KICAgICAgfQ0KICAgIH0",
		...(onSs ? ["ICAgIHsNCiAgICAgICJ0eXBlIjogInNoYWRvd3NvY2tzIiwNCiAgICAgICJ0YWciOiAiI3JlbWFya3MjIiwNCiAgICAgICJzZXJ2ZXIiOiAiI3NlcnZlciMiLA0KICAgICAgInNlcnZlcl9wb3J0IjogI3BvcnQjLA0KICAgICAgIm1ldGhvZCI6ICJub25lIiwNCiAgICAgICJwYXNzd29yZCI6ICJub25lIiwNCiAgICAgICJwbHVnaW4iOiAidjJyYXktcGx1Z2luIiwNCiAgICAgICJwbHVnaW5fb3B0cyI6ICIjdGxzdHIjbXV4PTA7bW9kZT13ZWJzb2NrZXQ7cGF0aD0jcGF0aCM7aG9zdD0jaG9zdE5hbWUjIg0KICAgIH0"] : []),
	];

	// 待填充到outbounds里面分组的指定outbounds中
	let nStr = [];
	// 待填充到顶层outbounds的数组中
	let outbds = [];
	for (let addr of ipsArray) {
		if (!addr) continue;
		let port = (defaultPort !== 0) ? defaultPort : getRandomElement(ports);
		let remarks = `cfwks-${addr}:${port}`;
		let replacements = {
			'#remarks#': remarks,
			'#server#': addr,
			'#port#': port,
			'#uuid4#': uuid,
			'#password#': password,
			'#tls#': !isWorkersDevDomain,
			'#hostName#': hostName,
			'#path#': path,
			'#fp#': atob(getRandomElement(base64Fp)),
			'#tlstr#': isWorkersDevDomain ? "" : "tls;"
		};
		let regex = new RegExp(Object.keys(replacements).join('|'), 'g');
		let oValue = base64Decode(getRandomElement(jsonArr)).replace(regex, (match) => replacements[match]);
		if (!nStr.includes(remarks)) {
			outbds.push(oValue);
			nStr.push(remarks);
		}
	}

	return [nStr, outbds];
}

export function buildYamls(ipsArray, subParameter, hostName, nodePath = "/", defaultPort = 0) {
	let isWorkersDevDomain = hostName.endsWith(atob("LndvcmtlcnMuZGV2"));
	let ports = isWorkersDevDomain ? HTTP_WITH_PORTS : HTTPS_WITH_PORTS;
	let { uuid, password, onSs } = subParameter;
	let path = nodePath;
	let yamlArr = [
		"ICAtIHsidHlwZSI6InZsZXNzIiwibmFtZSI6IiNyZW1hcmtzIyIsInNlcnZlciI6IiNzZXJ2ZXIjIiwicG9ydCI6I3BvcnQjLCJ1dWlkIjoiI3V1aWQ0IyIsIm5ldHdvcmsiOiJ3cyIsInRscyI6I3RscyMsInVkcCI6ZmFsc2UsInNlcnZlcm5hbWUiOiIiLCJjbGllbnQtZmluZ2VycHJpbnQiOiIjZnAjIiwic2tpcC1jZXJ0LXZlcmlmeSI6dHJ1ZSwid3Mtb3B0cyI6eyJwYXRoIjoiI3BhdGgjIiwiaGVhZGVycyI6eyJIb3N0IjoiI2hvc3ROYW1lIyJ9fX0=",
		"ICAtIHsidHlwZSI6InRyb2phbiIsIm5hbWUiOiIjcmVtYXJrcyMiLCJzZXJ2ZXIiOiIjc2VydmVyIyIsInBvcnQiOiNwb3J0IywicGFzc3dvcmQiOiIjcGFzc3dvcmQjIiwibmV0d29yayI6IndzIiwidWRwIjpmYWxzZSwic25pIjoiIiwiY2xpZW50LWZpbmdlcnByaW50IjoiI2ZwIyIsInNraXAtY2VydC12ZXJpZnkiOnRydWUsIndzLW9wdHMiOnsicGF0aCI6IiNwYXRoIyIsImhlYWRlcnMiOnsiSG9zdCI6IiNob3N0TmFtZSMifX19",
		...(onSs ? ["ICAtIHsidHlwZSI6InNzIiwibmFtZSI6IiNyZW1hcmtzIyIsInNlcnZlciI6IiNzZXJ2ZXIjIiwicG9ydCI6I3BvcnQjLCJjaXBoZXIiOiJub25lIiwicGFzc3dvcmQiOiJub25lIiwicGx1Z2luIjoidjJyYXktcGx1Z2luIiwicGx1Z2luLW9wdHMiOnsibW9kZSI6IndlYnNvY2tldCIsInRscyI6I3RscyMsImhvc3QiOiIjaG9zdE5hbWUjIiwicGF0aCI6IiNwYXRoIyIsIm11eCI6ZmFsc2V9LCJ1ZHAiOmZhbHNlfQ"] : []),
	];

	// 待填充到proxy-groups里面指定的proxies中
	let nStr = [];
	// 待填充到顶层proxies的数组中
	let poies = [];
	for (let addr of ipsArray) {
		if (!addr) continue;
		let port = (defaultPort !== 0) ? defaultPort : getRandomElement(ports);
		let remarks = `cfwks-${addr}:${port}`;
		let replacements = {
			'#remarks#': remarks,
			'#server#': addr,
			'#port#': port,
			'#uuid4#': uuid,
			'#password#': password,
			'#tls#': !isWorkersDevDomain,
			'#hostName#': hostName,
			'#path#': path,
			'#fp#': atob(getRandomElement(base64Fp))
		};
		let regex = new RegExp(Object.keys(replacements).join('|'), 'g');
		let pValue = base64Decode(getRandomElement(yamlArr)).replace(regex, (match) => replacements[match]);
		if (!nStr.includes(remarks)) {
			poies.push(pValue);
			nStr.push(remarks);
		}
	}

	return [nStr, poies];
}
