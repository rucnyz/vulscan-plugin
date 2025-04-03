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

// Store the latest analysis result for showing detailed explanation
let lastAnalysisResult: AnalysisResponse | null = null;

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('Congratulations, your extension "vulscan" is now active!');

	// Register document save event listener for automatic analysis
	// Moving this up to initialize it before other commands
	const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
		// Check if auto-analysis is enabled in configuration
		const config = vscode.workspace.getConfiguration('vulscan');
		const autoAnalyzeOnSave = config.get('autoAnalyzeOnSave') as boolean || false;
		
		console.log(`Auto-analyze on save: ${autoAnalyzeOnSave}`);
		
		if (autoAnalyzeOnSave) {
			await analyzeDocumentOnSave(document);
		}
	});

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
			lastAnalysisResult = pred; // Store for detailed explanation
			const decorationType = getDecorationForResult(pred);

			editor.setDecorations(decorationType, [selection]);

			// Display the result with a button for detailed explanation
			if (pred.status === VulnerabilityStatus.Vulnerable) {
				vscode.window.showErrorMessage(
					`Vulnerability detected: ${pred.cweType}`, 
					{ modal: false }, 
					'Show Details'
				).then(selection => {
					if (selection === 'Show Details') {
						showDetailedExplanation();
					}
				});
			} else {
				vscode.window.showInformationMessage(
					'Code appears to be benign',
					{ modal: false },
					'Show Details'
				).then(selection => {
					if (selection === 'Show Details') {
						showDetailedExplanation();
					}
				});
			}
		} catch (error) {
			vscode.window.showErrorMessage(`Error analyzing code: ${error}`);
		}
	});

	// Register a command to clear all decorations
	const clearDecorations = vscode.commands.registerCommand('vulscan.clearDecorations', () => {
		clearAllDecorations();
		vscode.window.showInformationMessage('Cleared all vulnerability highlights');
	});

	// Register a command to show detailed explanation
	const showDetailsCommand = vscode.commands.registerCommand('vulscan.showDetails', () => {
		showDetailedExplanation();
	});

	// Explicitly register a command to toggle auto-analyze on save
	const toggleAutoAnalyzeCommand = vscode.commands.registerCommand('vulscan.toggleAutoAnalyze', () => {
		const config = vscode.workspace.getConfiguration('vulscan');
		const currentValue = config.get('autoAnalyzeOnSave') as boolean || false;
		config.update('autoAnalyzeOnSave', !currentValue, vscode.ConfigurationTarget.Global)
			.then(() => {
				vscode.window.showInformationMessage(
					`Auto-analyze on save is now ${!currentValue ? 'enabled' : 'disabled'}`
				);
			});
	});

	// Listen for configuration changes
	const configListener = vscode.workspace.onDidChangeConfiguration((e) => {
		if (e.affectsConfiguration('vulscan.autoAnalyzeOnSave')) {
			const config = vscode.workspace.getConfiguration('vulscan');
			const autoAnalyzeOnSave = config.get('autoAnalyzeOnSave') as boolean || false;
			console.log(`Configuration changed: Auto-analyze on save: ${autoAnalyzeOnSave}`);
		}
	});

	// Add all subscriptions
	context.subscriptions.push(
		analyzeCodeCommand, 
		clearDecorations, 
		onSaveListener, 
		showDetailsCommand, 
		toggleAutoAnalyzeCommand,
		configListener
	);

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

	// Force activation of the auto-analyze feature by checking current editor
	const activeEditor = vscode.window.activeTextEditor;
	if (activeEditor) {
		const config = vscode.workspace.getConfiguration('vulscan');
		if (config.get('autoAnalyzeOnSave') as boolean) {
			// Log activation status
			console.log('Auto-analyze feature activated with current editor');
		}
	}
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

/**
 * Shows detailed explanation of the last analysis result in a read-only editor
 */
function showDetailedExplanation() {
    if (!lastAnalysisResult || !lastAnalysisResult.response) {
        vscode.window.showInformationMessage('No detailed explanation available.');
        return;
    }

    // Create a read-only webview panel to display the explanation
    const panel = vscode.window.createWebviewPanel(
        'vulnerabilityDetails', // Identifier
        'Vulnerability Analysis Details', // Title
        vscode.ViewColumn.Beside, // Show in beside group
        {
            enableScripts: true, // Enable scripts for markdown rendering
            localResourceRoots: [], // Restrict loading resources
            retainContextWhenHidden: true // Keep content when hidden
        }
    );

    // Set HTML content with the formatted explanation
    panel.webview.html = getWebviewContent(lastAnalysisResult);
}

/**
 * Format the HTML content for the webview panel
 */
function getWebviewContent(result: AnalysisResponse): string {
    const vulnerableStyle = 'color: #d73a49; background-color: rgba(255, 0, 0, 0.1); padding: 5px;';
    const benignStyle = 'color: #22863a; background-color: rgba(0, 255, 0, 0.1); padding: 5px;';
    const statusStyle = result.status === VulnerabilityStatus.Vulnerable ? vulnerableStyle : benignStyle;
    const statusEmoji = result.status === VulnerabilityStatus.Vulnerable ? '⚠️' : '✅';
    const statusText = result.status === VulnerabilityStatus.Vulnerable ? 'Vulnerable' : 'Benign';
    
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Analysis Details</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                    padding: 20px;
                    line-height: 1.6;
                }
                h1 {
                    border-bottom: 1px solid #eaecef;
                    padding-bottom: 10px;
                    margin-bottom: 20px;
                }
                h2 {
                    margin-top: 24px;
                    margin-bottom: 16px;
                    font-weight: 600;
                }
                .status {
                    font-weight: bold;
                    display: inline-block;
                    border-radius: 3px;
                    ${statusStyle}
                }
                .explanation {
                    background-color: #f6f8fa;
                    border-radius: 3px;
                    padding: 16px;
                }
                pre {
                    background-color: #f3f3f3;
                    padding: 10px;
                    border-radius: 3px;
                    overflow-x: auto;
                }
                code {
                    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
                    font-size: 0.9em;
                }
                blockquote {
                    border-left: 4px solid #ddd;
                    padding-left: 16px;
                    margin-left: 0;
                    color: #555;
                }
            </style>
            <!-- Include markdown-it for rendering -->
            <script src="https://cdnjs.cloudflare.com/ajax/libs/markdown-it/12.3.2/markdown-it.min.js"></script>
        </head>
        <body>
            <h1>Code Analysis Results</h1>
            
            <h2>Status</h2>
            <div class="status">${statusEmoji} ${statusText}</div>
            
            ${result.cweType ? `<h2>Vulnerability Type</h2><div>${result.cweType}</div>` : ''}
            
            <h2>Detailed Explanation</h2>
            <div class="explanation" id="markdown-content"></div>
            
            <script>
                // Safely render markdown
                const md = window.markdownit({
                    html: false,
                    linkify: true,
                    typographer: true
                });
                
                // Set the markdown content
                const content = ${JSON.stringify(result.response || '')};
                document.getElementById('markdown-content').innerHTML = md.render(content);
            </script>
        </body>
        </html>
    `;
}

/**
 * Analyzes the entire document or code chunks when a file is saved
 * @param document The document that was saved
 */
async function analyzeDocumentOnSave(document: vscode.TextDocument): Promise<void> {
	// Find the editor for this document
	const editor = vscode.window.visibleTextEditors.find(editor => editor.document.uri === document.uri);
	if (!editor) {
		console.log('No editor found for saved document');
		return;
	}

	console.log(`Analyzing saved document: ${document.fileName}`);

	// Clear previous decorations first
	clearAllDecorations();
	
	// Get file content
	const fileContent = document.getText();
	
	try {
		// Option 1: Analyze the entire file
		const result = await analyzeCodeForVulnerabilities(fileContent);
		const pred = result.result;
		lastAnalysisResult = pred; // Store for detailed explanation
		
		if (pred.status === VulnerabilityStatus.Vulnerable) {
			// Create a decoration for the entire document
			const fullDocumentRange = new vscode.Range(
				document.positionAt(0),
				document.positionAt(fileContent.length)
			);
			
			const decorationType = getDecorationForResult(pred);
			editor.setDecorations(decorationType, [fullDocumentRange]);
			
			vscode.window.showWarningMessage(
				`Auto-scan found vulnerability: ${pred.cweType}`,
				{ modal: false },
				'Show Details'
			).then(selection => {
				if (selection === 'Show Details') {
					showDetailedExplanation();
				}
			});
		} else {
			// Add feedback for benign files too
			console.log('File analyzed and appears to be benign');
		}
	} catch (error) {
		console.error('Error analyzing file on save:', error);
	}
}

// This method is called when your extension is deactivated
export function deactivate() { 
	clearAllDecorations();
}
