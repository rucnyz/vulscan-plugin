import * as vscode from 'vscode';
import * as https from 'https';

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
			const decorationType = getDecorationForResult(result);
			
			editor.setDecorations(decorationType, [selection]);
			
			// Display the result
			if (result.status === 'vulnerable') {
				vscode.window.showErrorMessage(`Vulnerability detected: ${result.cweType}`);
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

	context.subscriptions.push(disposable);
	context.subscriptions.push(analyzeCodeCommand);
	
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
 * Send the code to an API for vulnerability analysis
 * @param code The code to analyze
 * @returns Analysis result
 */
async function analyzeCodeForVulnerabilities(code: string): Promise<{status: 'benign' | 'vulnerable', cweType?: string}> {
	// Replace with your actual API endpoint
	const apiUrl = 'https://your-vulnerability-api.com/analyze';
	
	return new Promise((resolve, reject) => {
		// This is a placeholder implementation
		// In a real scenario, you'd make an actual HTTP request to your API
		
		// For demo purposes, let's simulate an API call with setTimeout
		setTimeout(() => {
			// Mock response - replace with actual API call
			const mockResponses: {status: 'benign' | 'vulnerable', cweType?: string}[] = [
				{ status: 'benign' },
				{ status: 'vulnerable', cweType: 'CWE-79: Cross-site Scripting' },
				{ status: 'vulnerable', cweType: 'CWE-89: SQL Injection' }
			];
			
			const response = mockResponses[Math.floor(Math.random() * mockResponses.length)];
			resolve(response);
			
			// Real implementation would be something like:
			/*
			const req = https.request(apiUrl, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				}
			}, (res) => {
				let data = '';
				res.on('data', (chunk) => {
					data += chunk;
				});
				res.on('end', () => {
					try {
						const response = JSON.parse(data);
						resolve(response);
					} catch (e) {
						reject('Failed to parse API response');
					}
				});
			});
			
			req.on('error', (error) => {
				reject(error.message);
			});
			
			req.write(JSON.stringify({ code }));
			req.end();
			*/
		}, 1000);
	});
}

/**
 * Get the appropriate decoration type based on analysis result
 */
function getDecorationForResult(result: {status: 'benign' | 'vulnerable', cweType?: string}): vscode.TextEditorDecorationType {
	if (result.status === 'vulnerable') {
		// Create a custom decoration for this specific vulnerability
		return vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(255, 0, 0, 0.2)',
			after: {
				contentText: ` ⚠️ ${result.cweType || 'Vulnerability'}`,
				color: 'red'
			}
		});
	} else {
		return vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(0, 255, 0, 0.2)',
			after: {
				contentText: ' ✓ Benign',
				color: 'green'
			}
		});
	}
}

// This method is called when your extension is deactivated
export function deactivate() {}
