import * as path from 'path';
import { globSync } from 'glob';

export function run(): Promise<void> {
    return new Promise((resolve, reject) => {
        try {
            const Mocha = require('mocha');
            
            const mocha = new Mocha({
                ui: 'tdd',
                color: true
            });

            const testsRoot = path.resolve(__dirname, '..');
            
            // 使用 globSync 方法
            const files = globSync('**/**.test.js', { cwd: testsRoot });
            
            // Add files to the test suite
            files.forEach((f: string) => mocha.addFile(path.resolve(testsRoot, f)));

            try {
                // Run the mocha test
                mocha.run((failures: number) => {
                    if (failures > 0) {
                        reject(new Error(`${failures} tests failed.`));
                    } else {
                        resolve();
                    }
                });
            } catch (err) {
                console.error(err);
                reject(err);
            }
        } catch (err) {
            reject(err);
        }
    });
}