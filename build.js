import { build } from 'esbuild';
import { minify } from 'terser';
import { readFile, writeFile } from 'fs/promises';

const entries = ['src/worker-基础版.js', 'src/worker.js'];
const entry = entries[1]; // 手动改为0或1
const baseName = entry.split('/').pop().replace('.js', '');

const builds = [
	{
		format: 'esm',
		outfile: `dist/${baseName}.js`, // ESModule格式
		minify: false,
	},
	{
		format: 'esm',
		outfile: `_${baseName}.js`, // ESM + Terser压缩
		minify: true,
		terser: true, // 进一步混淆，可选
	},
];

for (const options of builds) {
	const result = await build({
		entryPoints: [entry],
		bundle: true,
		platform: 'browser',
		format: options.format,
		outfile: options.outfile,
		sourcemap: false,
		minify: options.minify,
		// drop: ["console"],
		external: ["cloudflare:sockets"],
	});

	if (options.terser) {
		const code = await readFile(options.outfile, 'utf8');
		const terserResult = await minify(code, {
			compress: true,
			mangle: true,
		});
		await writeFile(options.outfile, terserResult.code, 'utf8');
		console.log(`Minified with terser: ${options.outfile}`);
	} else {
		console.log(`Built: ${options.outfile}`);
	}
}
