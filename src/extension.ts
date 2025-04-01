import * as vscode from 'vscode';
import * as https from 'https';

// Define enum for vulnerability status
enum VulnerabilityStatus {
    Benign = 'no',
    Vulnerable = 'yes'
}

// Define interfaces for the analysis result
interface AnalysisResponse {
    status: VulnerabilityStatus;
    cweType?: string;
    model?: string;
    response?: string;
    usage?: any;
}

interface AnalysisResult {
    result: AnalysisResponse;
    status: 'success' | 'error';
}

// Track active decorations
let activeDecorations: vscode.TextEditorDecorationType[] = [];

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('Congratulations, your extension "vulscan" is now active!');

	// Register a command to analyze selected code for vulnerabilities
	const analyzeCodeCommand = vscode.commands.registerCommand('vulscan.analyzeCode', async () => {
		const editor = vscode.window.activeTextEditor;
		if (!editor) {
			vscode.window.showInformationMessage('No editor is active');
			return;
		}

		const selection = editor.selection;
		if (selection.isEmpty) {
			vscode.window.showInformationMessage('Please select some code to analyze');
			return;
		}

		const selectedText = editor.document.getText(selection);
		vscode.window.showInformationMessage('Analyzing code for vulnerabilities...');

		try {
			const result = await analyzeCodeForVulnerabilities(selectedText);
			const pred = result.result;
			const decorationType = getDecorationForResult(pred);

			editor.setDecorations(decorationType, [selection]);

			// Display the result
			if (pred.status === VulnerabilityStatus.Vulnerable) {
				vscode.window.showErrorMessage(`Vulnerability detected: ${pred.cweType}`);
			} else {
				vscode.window.showInformationMessage('Code appears to be benign');
			}
		} catch (error) {
			vscode.window.showErrorMessage(`Error analyzing code: ${error}`);
		}
	});

	// Register the hello world command (existing code)
	const disposable = vscode.commands.registerCommand('vulscan.helloWorld', () => {
		// The code you place here will be executed every time your command is executed
		// Display a message box to the user
		vscode.window.showInformationMessage('Hello World from vulscan!');
	});

	// Register a command to clear all decorations
	const clearDecorations = vscode.commands.registerCommand('vulscan.clearDecorations', () => {
		clearAllDecorations();
		vscode.window.showInformationMessage('Cleared all vulnerability highlights');
	});

	context.subscriptions.push(disposable);
	context.subscriptions.push(analyzeCodeCommand);
	context.subscriptions.push(clearDecorations);

	// Create decoration types for vulnerabilities and benign code
	const vulnerableDecorationType = vscode.window.createTextEditorDecorationType({
		backgroundColor: 'rgba(255, 0, 0, 0.2)',
		after: {
			contentText: ' ⚠️ ',
			color: 'red'
		}
	});

	const benignDecorationType = vscode.window.createTextEditorDecorationType({
		backgroundColor: 'rgba(0, 255, 0, 0.2)',
		after: {
			contentText: ' ✓ ',
			color: 'green'
		}
	});

	// Store the decoration types in context for later use
	context.globalState.update('vulnerableDecorationType', vulnerableDecorationType);
	context.globalState.update('benignDecorationType', benignDecorationType);
}

/**
 * Clear all active decorations
 */
function clearAllDecorations() {
	activeDecorations.forEach(decoration => {
		decoration.dispose();
	});
	activeDecorations = [];
}

/**
 * Send the code to an API for vulnerability analysis
 * @param code The code to analyze
 * @returns Analysis result
 */
async function analyzeCodeForVulnerabilities(code: string): Promise<AnalysisResult> {
	// Get API endpoint from configuration or use default
	const config = vscode.workspace.getConfiguration('vulscan');
	const apiUrl = config.get('apiUrl') as string || 'http://128.111.28.87:8002/analyze';

	return new Promise((resolve, reject) => {
		// Parse URL to determine if http or https should be used
		const isHttps = apiUrl.startsWith('https');
		const http = isHttps ? require('https') : require('http');

		const urlObj = new URL(apiUrl);

		const options = {
			hostname: urlObj.hostname,
			port: urlObj.port || (isHttps ? 443 : 80),
			path: urlObj.pathname,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			}
		};

		const req = http.request(options, (res: any) => {
			let data = '';

			// Handle HTTP status errors
			if (res.statusCode < 200 || res.statusCode >= 300) {
				return reject(new Error(`API responded with status code ${res.statusCode}`));
			}

			res.on('data', (chunk: any) => {
				data += chunk;
			});

			res.on('end', () => {
				try {
					const response = JSON.parse(data);
					resolve(response);
				} catch (e) {
					reject(new Error(`Failed to parse API response: ${e}`));
				}
			});
		});

		req.on('error', (error: any) => {
			reject(new Error(`API request failed: ${error.message}`));
		});

		// Send the code to analyze
		const requestBody = JSON.stringify({ code });
		req.write(requestBody);
		req.end();
	});
}

/**
 * Get the appropriate decoration type based on analysis result
 */
function getDecorationForResult(result: AnalysisResponse): vscode.TextEditorDecorationType {
	let decorationType;
	if (result.status === VulnerabilityStatus.Vulnerable) {
		// Create a custom decoration for this specific vulnerability
		decorationType = vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(255, 0, 0, 0.2)',
			after: {
				contentText: ` ⚠️ ${result.cweType || 'Vulnerability'}`,
				color: 'red'
			}
		});
	} else {
		decorationType = vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(0, 255, 0, 0.2)',
			after: {
				contentText: ' ✓ Benign',
				color: 'green'
			}
		});
	}
	
	// Add to active decorations for tracking
	activeDecorations.push(decorationType);
	return decorationType;
}

// This method is called when your extension is deactivated
export function deactivate() { 
	clearAllDecorations();
}
