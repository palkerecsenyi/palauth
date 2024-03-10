import * as path from "path"
import { fileURLToPath } from "url"

export default {
    entry: "./src/index.ts",
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: "ts-loader",
            },
        ],
    },
    resolve: {
        extensions: [".ts", ".tsx"],
        alias: {
            react: "preact/compat",
            "react-dom": "preact/compat",
            "react/jsx-runtime": "preact/jsx-runtime",
        },
    },
    output: {
        filename: "webauthn.js",
        path: path.resolve(
            path.dirname(fileURLToPath(import.meta.url)),
            "../backend",
            "static/js",
        ),
    },
}
