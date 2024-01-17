import * as path from "path"
import {fileURLToPath} from "url";

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
        extensions: [".ts", ".js"],
    },
    output: {
        filename: "webauthn.js",
        path: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../backend", "static/js"),
    }
}
