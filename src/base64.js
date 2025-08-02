/**
 * 将UTF8字符串进行Base64编码
 *
 * 该函数，适合bytes数组长度过大（如超过数万个字节）的，
 * 已解决了 "RangeError: Maximum call stack size exceeded" 错误，
 * 也就是该函数解决了超出调用栈的最大限制错误
 * @param {*} str
 * @returns
 */
export function base64Encode(str) {
	let encoder = new TextEncoder();
	let bytes = encoder.encode(str);
	let binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
	return btoa(binary);
}

// base64解密
export function base64Decode(base64Str) {
	let binary = atob(base64Str);
	let bytes = new Uint8Array([...binary].map((char) => char.charCodeAt(0)));
	let decoder = new TextDecoder();
	return decoder.decode(bytes);
}
