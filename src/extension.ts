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
interface ExtractResponse {
	dependencies: string[];
	done?: boolean;
}
interface AnalysisResult {
	result: AnalysisResponse;
	status: 'success' | 'error';
}

interface ExtractResult {
	result: ExtractResponse;
	status: 'success' | 'error';
}
// Track active decorations
let activeDecorations: vscode.TextEditorDecorationType[] = [];

// Store the latest analysis result for showing detailed explanation
let lastAnalysisResult: AnalysisResponse | null = null;

// Define a global API base URL
let apiBaseUrl: string = "http://api.virtueai.io/api/vulscan";

// Store analysis results by function/method
interface FunctionAnalysisResult {
    functionSymbol: vscode.DocumentSymbol;
    result: AnalysisResponse;
    codeHash: string; // Add this field to track code changes
}

// Map to store analysis results by document URI
const documentAnalysisResults = new Map<string, FunctionAnalysisResult[]>();

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
	// Get API base URL from configuration
	const config = vscode.workspace.getConfiguration('vulscan');
	apiBaseUrl = config.get('apiBaseUrl') as string || apiBaseUrl;
	console.log(`Using API base URL: ${apiBaseUrl}`);

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
			// Replace fixed rounds with a loop that continues until done or max rounds reached
			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: "Extracting dependencies",
				cancellable: false
			}, async (progress) => {
				let round = 1;
				let isDone = false;
				const MAX_ROUNDS = 5;

				while (!isDone && round <= MAX_ROUNDS) {
					// Extract dependencies for current round
					const result = await extractDependencies(selectedText, round);

					// Display dependencies
					if (result.dependencies.length > 0) {
						progress.report({ message: result.dependencies.join(", ") });
					} else {
						progress.report({ message: `Round ${round}: No dependencies found` });
					}

					// Check if extraction is complete
					isDone = result.done || false;
					round++;
				}

				if (round > MAX_ROUNDS && !isDone) {
					progress.report({ message: "Reached maximum extraction rounds" });
				}
			});

			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: "Reducing dependencies",
				cancellable: false
			}, async (progress) => {
				await new Promise(resolve => setTimeout(resolve, 300));
			});

			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: "Querying model",
				cancellable: false
			}, async (progress) => {

				// Gather implementations of functions called in the selected code
				const implementationsPromises: Promise<string>[] = [];

				// First get all document symbols
				const symbols = await getDocumentSymbols(editor.document);

				// Filter symbols that are within the selection range
				const symbolsInSelection = symbols.filter(symbol =>
					selection.contains(symbol.range) ||
					symbol.range.contains(selection) ||
					selection.intersection(symbol.range)
				);

				console.log(`Found ${symbolsInSelection.length} symbols in the selected code`);

				// For each symbol, try to get implementations
				for (const symbol of symbolsInSelection) {
					// Use the symbol's selection range (usually the name of the symbol)
					const position = symbol.selectionRange.start;

					const implPromise = (vscode.commands.executeCommand<vscode.Location[]>(
						'vscode.executeImplementationProvider',
						editor.document.uri,
						position
					) as Promise<vscode.Location[]>).then(locations => {
						if (locations && locations.length > 0) {
							// Get the content of each implementation
							return Promise.all(locations.map(async location => {
								try {
									const document = await vscode.workspace.openTextDocument(location.uri);
									return document.getText(location.range);
								} catch (error) {
									console.error('Error getting implementation:', error);
									return '';
								}
							})).then(implementations => implementations.join('\n\n'));
						}
						return '';
					}).catch(error => {
						console.error('Error executing implementation provider:', error);
						return '';
					});

					implementationsPromises.push(implPromise);
				}

				// Also check for function calls within the selection that might not be captured by symbols
				// Get relevant positions for function calls (more targeted approach)
				for (let line = selection.start.line; line <= selection.end.line; line++) {
					const lineText = editor.document.lineAt(line).text;

					// Use regex to find potential function calls in the line
					const functionCallPattern = /\b\w+\s*\(/g;
					let match;

					while ((match = functionCallPattern.exec(lineText)) !== null) {
						const callPosition = new vscode.Position(line, match.index);

						// Check if this position is within our selection
						if (selection.contains(callPosition)) {
							const implPromise = Promise.resolve(vscode.commands.executeCommand<vscode.Location[]>(
								'vscode.executeImplementationProvider',
								editor.document.uri,
								callPosition
							)).then(locations => {
								if (locations && locations.length > 0) {
									return Promise.all(locations.map(async location => {
										try {
											const document = await vscode.workspace.openTextDocument(location.uri);
											return document.getText(location.range);
										} catch (error) {
											console.error('Error getting implementation:', error);
											return '';
										}
									})).then(implementations => implementations.join('\n\n'));
								}
								return '';
							}).catch(error => {
								console.error('Error executing implementation provider:', error);
								return '';
							});

							implementationsPromises.push(implPromise);
						}
					}
				}

				// Wait for all implementation queries to complete
				const implementations = await Promise.all(implementationsPromises);
				const implementationsText = implementations.filter(impl => impl.length > 0).join('\n\n');

				// Combine selected code with implementations for analysis
				const codeToAnalyze = `
// Context
${implementationsText}
// Original selected code
${selectedText}
`;

				console.log('Analyzing code with implementations included');
				// const result = mockResult; // Use mock result
				const result = await analyzeCodeForVulnerabilities(codeToAnalyze);
				const pred = result.result;
				lastAnalysisResult = pred; // Store for detailed explanation
				const decorationType = getDecorationForResult(pred);

				editor.setDecorations(decorationType, [selection]);

				// Display the result with a button for detailed explanation
				if (pred.status === VulnerabilityStatus.Vulnerable) {
					vscode.window.showErrorMessage(
						`Vulnerability detected: ${pred.cweType}`,
						{ modal: false },
						'Show Details',
						'Suggestions for Improvement'
					).then(selection => {
						if (selection === 'Show Details') {
							showDetailedExplanation();
						} else if (selection === 'Suggestions for Improvement') {
							showImprovementSuggestions(pred);
						}
					});
				} else {
					vscode.window.showInformationMessage(
						'Code appears to be benign',
						{ modal: false },
						'Show Details',
					).then(selection => {
						if (selection === 'Show Details') {
							showDetailedExplanation();
						} else if (selection === 'Suggestions for Improvement') {
							showImprovementSuggestions(pred);
						}
					});
				}
			});
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

	// Register CodeLens provider
	const codeLensProvider = new VulnerabilityScanCodeLensProvider();
	const codeLensProviderDisposable = vscode.languages.registerCodeLensProvider(
		{ scheme: 'file' },
		codeLensProvider
	);
	
	// Add CodeLens provider to subscriptions
	context.subscriptions.push(codeLensProviderDisposable);

	// Register command to show function details from CodeLens
	const showFunctionDetailsCommand = vscode.commands.registerCommand(
		'vulscan.showFunctionDetails', 
		(documentUri: string, line: number, result: AnalysisResponse) => {
			showFunctionDetails(documentUri, line, result);
		}
	);
	
	// Add command to subscriptions
	context.subscriptions.push(showFunctionDetailsCommand);
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
	// Get the full API URL for analyze endpoint
	const apiUrl = `${apiBaseUrl}/analyze`;

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

	// Add message handler for opening files
	panel.webview.onDidReceiveMessage(
		async message => {
			if (message.command === 'openFile') {
				try {
					const uri = vscode.Uri.file(message.filePath);
					const document = await vscode.workspace.openTextDocument(uri);
					const editor = await vscode.window.showTextDocument(document, {
						viewColumn: vscode.ViewColumn.One,
						preview: true
					});

					// Move cursor to specified line if provided
					if (message.line !== undefined) {
						const position = new vscode.Position(message.line, 0);
						editor.selection = new vscode.Selection(position, position);
						editor.revealRange(
							new vscode.Range(position, position),
							vscode.TextEditorRevealType.InCenter
						);
					}
				} catch (error) {
					vscode.window.showErrorMessage(`Failed to open file: ${error}`);
				}
			}
			else {
				console.error(`Unknown command: ${message.command}`);
			}
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
	let functionReferences = '';
	// Define file references with proper paths and lines
	if (result.cweType === 'CWE-416') {
		functionReferences = `
        <h2>Function References</h2>
        <ul>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 967); return false;"><strong>font->ParseTable</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 587); return false;"><strong>GetTableData</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 1162); return false;"><strong>table->Parse</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 79); return false;"><strong>arena.Allocate</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 1070); return false;"><strong>AddTable</strong></a></li>
        </ul>
    `;
	}
	else if (result.cweType === 'CWE-200'){
		functionReferences = `
        <h2>Function References</h2>
        <ul>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/server/middlewares/static.ts', 264); return false;"><strong>ensureServingAccess</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 353); return false;"><strong>rawRE</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 352); return false;"><strong>urlRE</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/server/middlewares/static.ts', 223); return false;"><strong>isFileServingAllowed</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 269); return false;"><strong>fsPathFromUrl</strong></a></li>
			<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 262); return false;"><strong>fsPathFromId</strong></a></li>
			<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/shared/utils.ts', 31); return false;"><strong>cleanUrl</strong></a></li>
			<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 256); return false;"><strong>VOLUME_RE</strong></a></li>			
			<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/shared/utils.ts', 30); return false;"><strong>postfixRE</strong></a></li>
			<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 258); return false;"><strong>normalizePath</strong></a></li>			
			<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/server/middlewares/static.ts', 247); return false;"><strong>isFileLoadingAllowed</strong></a></li>
        </ul>
    `;
	}


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
                ul {
                    padding-left: 20px;
                }
                li {
                    margin-bottom: 8px;
                }
                a {
                    color: #0366d6;
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                }
                .function-ref {
                    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
                    background-color: #f3f3f3;
                    padding: 2px 4px;
                    border-radius: 3px;
                }
            </style>
            <!-- Include markdown-it for rendering -->
            <script src="https://cdnjs.cloudflare.com/ajax/libs/markdown-it/12.3.2/markdown-it.min.js"></script>
            <script>
                // Only call acquireVsCodeApi once and store the reference
                const vscode = acquireVsCodeApi();
                
                // Function to open file via message to extension
                function openFile(filePath, line) {
                    vscode.postMessage({
                        command: 'openFile',
                        filePath: filePath,
                        line: line
                    });
                    return false; // Prevent default action
                }
                
                // Wait for the DOM to be fully loaded before rendering markdown
                document.addEventListener('DOMContentLoaded', () => {
                    // Safely render markdown
                    const md = window.markdownit({
                        html: false,
                        linkify: true,
                        typographer: true
                    });
                    
                    // Set the markdown content
                    const content = ${JSON.stringify(result.response || '')};
                    const markdownElement = document.getElementById('markdown-content');
                    if (markdownElement) {
                        markdownElement.innerHTML = md.render(content);
                    }
                    
                    // Add event listeners to all function reference links
                    document.querySelectorAll('a[onclick]').forEach(link => {
                        link.addEventListener('click', function(e) {
                            e.preventDefault(); // Prevent the default behavior
                        });
                    });
                });
            </script>
        </head>
        <body>
            <h1>Code Analysis Results</h1>
            
            <h2>Status</h2>
            <div class="status">${statusEmoji} ${statusText}</div>
            
            ${result.cweType ? `<h2>Vulnerability Type</h2><div>${result.cweType}</div>` : ''}
            
            <h2>Detailed Explanation</h2>
            <div class="explanation" id="markdown-content"></div>
            
            ${functionReferences}
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

	try {
		// Get document symbols to find functions/methods
		const symbols = await getDocumentSymbols(document);
		
		// Filter to only include function and method symbols
		// filter declarations
		const functionSymbols = symbols.filter(symbol => 
			(symbol.kind === vscode.SymbolKind.Function || 
			symbol.kind === vscode.SymbolKind.Method ||
			symbol.kind === vscode.SymbolKind.Constructor ) 
			&& !symbol.detail.includes("declaration")
			&& !symbol.name.startsWith("~")
		);
		
		if (functionSymbols.length === 0) {
			console.log('No functions or methods found in the document');
			return;
		}
		
		console.log(`Found ${functionSymbols.length} functions/methods to analyze`);
		
		// Initialize the analysis results array for this document if it doesn't exist
		if (!documentAnalysisResults.has(document.uri.toString())) {
			documentAnalysisResults.set(document.uri.toString(), []);
		}
		
		// Get the current results array
		const currentResults = documentAnalysisResults.get(document.uri.toString()) || [];
		
		// Track vulnerable functions count
		let vulnerableFunctionsCount = 0;
		
		await vscode.window.withProgress({
			location: vscode.ProgressLocation.Notification,
			title: "Analyzing functions",
			cancellable: true
		}, async (progress, token) => {
			// Create an array to store all analysis promises and their associated function symbols
			const analysisPromises: { 
				promise: Promise<AnalysisResult>; 
				functionSymbol: vscode.DocumentSymbol;
				code: string;
				codeHash: string;
				shouldAnalyze: boolean;
			}[] = [];
			
			// Create all analysis promises
			for (const functionSymbol of functionSymbols) {
				if (token.isCancellationRequested) {
					break;
				}
				
				// Extract the function's code
				const functionRange = functionSymbol.range;
				const functionCode = document.getText(functionRange);
				
				// Generate a hash of the function code to detect changes
				const codeHash = generateCodeHash(functionCode);
				
				// Check if we already have a result for this function with the same hash
				const existingResult = currentResults.find(r => 
					r.functionSymbol.name === functionSymbol.name && 
					r.codeHash === codeHash
				);
				
				// Determine if we need to analyze this function
				const shouldAnalyze = !existingResult;
				
				// If we already have a result for this function with the same code hash, reuse it
				if (existingResult) {
					console.log(`Reusing previous analysis for function: ${functionSymbol.name}`);
					
					// If the function is vulnerable, add its decoration
					if (existingResult.result.status === VulnerabilityStatus.Vulnerable) {
						vulnerableFunctionsCount++;
						const decorationType = getDecorationForResult(existingResult.result);
						editor.setDecorations(decorationType, [functionSymbol.range]);
					}
				}
				
				// Create the promise but don't await it yet
				analysisPromises.push({
					// Only create a real promise if we need to analyze
					promise: shouldAnalyze 
						? analyzeCodeForVulnerabilities(functionCode)
						: Promise.resolve({ 
							result: existingResult?.result || { status: VulnerabilityStatus.Benign },
							status: 'success' 
						}),
					functionSymbol,
					code: functionCode,
					codeHash,
					shouldAnalyze
				});
			}
			
			// Count how many functions actually need analysis
			const functionsToAnalyze = analysisPromises.filter(item => item.shouldAnalyze).length;
			
			// Report initial progress
			progress.report({ 
				message: `Sending ${functionsToAnalyze} analysis requests (${analysisPromises.length - functionsToAnalyze} cached)...`,
				increment: 5
			});
			
			// Process results as they complete
			let completedCount = 0;
			const incrementPerFunction = 95 / analysisPromises.length;
			
			// Process each promise as it completes
			await Promise.all(analysisPromises.map(async (item, index) => {
				try {
					// We already reported progress for cached functions, so only wait for ones we need to analyze
					const result = await item.promise;
					
					// If we've analyzed this function, create a new result object
					if (item.shouldAnalyze) {
						// Create the analysis result object with code hash
						const analysisResult = {
							functionSymbol: item.functionSymbol,
							result: result.result,
							codeHash: item.codeHash
						};
						
						// Update the stored analysis results immediately
						// Remove any existing result for this function
						const existingIndex = currentResults.findIndex(r => 
							r.functionSymbol.name === item.functionSymbol.name
						);
						
						if (existingIndex >= 0) {
							currentResults.splice(existingIndex, 1);
						}
						
						// Add the new result
						currentResults.push(analysisResult);
						
						// Update the map
						documentAnalysisResults.set(document.uri.toString(), currentResults);
						
						// If vulnerable, add decoration
						if (result.result.status === VulnerabilityStatus.Vulnerable) {
							vulnerableFunctionsCount++;
							const decorationType = getDecorationForResult(result.result);
							editor.setDecorations(decorationType, [item.functionSymbol.range]);
						}
					}
					
					// Update progress
					completedCount++;
					progress.report({ 
						message: `Analyzed ${completedCount}/${analysisPromises.length} functions (${analysisPromises.length - functionsToAnalyze} from cache)`,
						increment: incrementPerFunction 
					});
					
				} catch (error) {
					console.error(`Error analyzing function ${item.functionSymbol.name}:`, error);
					completedCount++;
					progress.report({ 
						message: `Error analyzing ${item.functionSymbol.name}`,
						increment: incrementPerFunction
					});
				}
			}));
		});
		
		// Show final notification about analysis results
		if (vulnerableFunctionsCount > 0) {
			// Show notification with count of vulnerable functions
			vscode.window.showWarningMessage(
				`Found ${vulnerableFunctionsCount} vulnerable functions. Check the CodeLens indicators for details.`
			);
		} else {
			vscode.window.showInformationMessage(
				'No vulnerabilities found in functions.'
			);
		}
	} catch (error) {
		console.error('Error analyzing file on save:', error);
	}
}

/**
 * Generates a simple hash of code content to detect changes
 * @param code The code to hash
 * @returns A string hash representation
 */
function generateCodeHash(code: string): string {
    // Simple hash function based on code length and character sums
    let hash = 0;
    for (let i = 0; i < code.length; i++) {
        const char = code.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString(16);
}

/**
 * Gets all document symbols using the document symbol provider
 * @param document The document to get symbols from
 * @returns Array of document symbols
 */
async function getDocumentSymbols(document: vscode.TextDocument): Promise<vscode.DocumentSymbol[]> {
	try {
		const symbolsResult = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>(
			'vscode.executeDocumentSymbolProvider',
			document.uri
		);

		if (!symbolsResult) {
			return [];
		}

		// Flatten nested symbols to get all symbols
		const flattenSymbols = (symbols: vscode.DocumentSymbol[]): vscode.DocumentSymbol[] => {
			return symbols.reduce((acc: vscode.DocumentSymbol[], symbol) => {
				acc.push(symbol);
				if (symbol.children && symbol.children.length > 0) {
					acc.push(...flattenSymbols(symbol.children));
				}
				return acc;
			}, []);
		};

		return flattenSymbols(symbolsResult);
	} catch (error) {
		console.error('Error getting document symbols:', error);
		return [];
	}
}

/**
 * Shows improvement suggestions in a webview panel
 * @param result The analysis result to generate suggestions for
 */
function showImprovementSuggestions(result: AnalysisResponse) {
	if (!result) {
		vscode.window.showInformationMessage('No analysis result available for improvement suggestions.');
		return;
	}

	// Create a webview panel to display the improvement suggestions
	const panel = vscode.window.createWebviewPanel(
		'improvementSuggestions',
		'Suggestions for Improvement',
		vscode.ViewColumn.Beside,
		{
			enableScripts: true,
			retainContextWhenHidden: true
		}
	);

	// Generate improvement suggestions based on the analysis result
	const suggestions = generateImprovementSuggestions(result);

	// Set HTML content with the formatted suggestions
	panel.webview.html = getImprovementSuggestionsContent(suggestions, result);
}

/**
 * Generates improvement suggestions based on the analysis result
 * @param result The analysis result
 * @returns Object containing suggestions and code examples
 */
function generateImprovementSuggestions(result: AnalysisResponse): {
	title: string;
	description: string;
	suggestions: { title: string; description: string; code?: string }[];
	isVulnerable: boolean;
} {
	const isVulnerable = result.status === VulnerabilityStatus.Vulnerable;

	if (isVulnerable) {
		// Suggestions for CWE-416: Use After Free
		if (result.cweType?.includes('CWE-416')) {
			return {
				title: "Fixing Use-After-Free Vulnerability",
				description: "The main issue is the mismatch between the lifetime of the Arena object and its allocations being used by the Font object. Here are some approaches to fix this vulnerability:",
				suggestions: [
					{
						title: "1. Make the Arena object a member of the Font class",
						description: "This ensures the Arena has the same lifetime as the Font object that uses its allocations:",
						code: `// Add Arena as a member variable to Font class
class Font {
private:
    ots::Arena m_arena;  // Add this member variable
    // ...existing members...

public:
    // ...existing methods...
    
    // Then modify ParseTable to use the member arena instead of a passed one
    bool ParseTable(/* params */) {
        // Use m_arena instead of a parameter
        if (GetTableData(data, table_entry, m_arena, &table_length, &table_data)) {
            // ...existing code...
        }
    }
};`
					},
					{
						title: "2. Use shared ownership for arena memory",
						description: "If modifying the Font class isn't feasible, use a shared_ptr to manage the Arena's lifetime:",
						code: `// In ProcessGeneric
std::shared_ptr<ots::Arena> arena_ptr = std::make_shared<ots::Arena>();

// Pass the shared_ptr to ParseTable
if (!font->ParseTable(it->second, data, arena_ptr)) {
    return OTS_FAILURE_MSG_TAG("Failed to parse table", tag);
}

// Modify ParseTable and GetTableData to accept shared_ptr<Arena>
bool Font::ParseTable(/* params */, std::shared_ptr<ots::Arena> arena) {
    // ...existing code...
    if (GetTableData(data, table_entry, arena, &table_length, &table_data)) {
        // ...existing code...
    }
}

// Store the shared_ptr in the Font class to keep the Arena alive
m_arenas.push_back(arena);  // m_arenas would be a member variable: std::vector<std::shared_ptr<ots::Arena>>`
					},
					{
						title: "3. Copy the allocated data instead of storing references",
						description: "Instead of storing pointers to arena-allocated memory, copy the data:",
						code: `if (GetTableData(data, table_entry, arena, &table_length, &table_data)) {
    // Create a copy of the data that the Font owns
    uint8_t* owned_data = new uint8_t[table_length];
    memcpy(owned_data, table_data, table_length);
    
    // Store the owned copy in the Font's tables
    m_tables[tag] = table;
    ret = table->Parse(owned_data, table_length);
    
    // Ensure proper cleanup in the Font's destructor
}`
					},
					{
						title: "4. Restructure the memory ownership model",
						description: "Redesign the relationship between Font and its data to have clearer ownership semantics:",
						code: `// Create a FontData class that owns all the font's data
class FontData {
private:
    std::map<uint32_t, std::vector<uint8_t>> table_data;
    
public:
    void AddTable(uint32_t tag, const uint8_t* data, size_t length) {
        table_data[tag].assign(data, data + length);
    }
    
    const uint8_t* GetTableData(uint32_t tag, size_t* length) {
        if (table_data.find(tag) != table_data.end()) {
            *length = table_data[tag].size();
            return table_data[tag].data();
        }
        return nullptr;
    }
};

// Font would then own a FontData object
class Font {
private:
    FontData m_data;
    // ...other members...
};`
					}
				],
				isVulnerable: true
			};
		}

		// Generic vulnerable code suggestions
		return {
			title: "Suggestions for Improving Code Security",
			description: "Based on the analysis, here are some general suggestions to improve your code's security:",
			suggestions: [
				{
					title: "1. Review memory management practices",
					description: "Ensure proper resource acquisition and release, considering the RAII pattern (Resource Acquisition Is Initialization)."
				},
				{
					title: "2. Use smart pointers when applicable",
					description: "Replace raw pointers with std::unique_ptr, std::shared_ptr, or std::weak_ptr to help manage object lifetimes."
				},
				{
					title: "3. Implement thorough input validation",
					description: "Validate all inputs thoroughly before processing them, especially for size fields and pointers."
				},
				{
					title: "4. Add unit tests for edge cases",
					description: "Create tests specifically targeting potential vulnerability scenarios to ensure they're properly handled."
				}
			],
			isVulnerable: true
		};
	} else {
		// Suggestions for benign code
		return {
			title: "Suggestions for Code Improvement",
			description: "Although no vulnerabilities were detected, here are some suggestions to improve your code quality:",
			suggestions: [
				{
					title: "1. Improve code readability",
					description: "Add clear comments, use descriptive variable names, and structure your code in a logical way."
				},
				{
					title: "2. Enhance error handling",
					description: "Implement comprehensive error handling to gracefully manage unexpected situations."
				},
				{
					title: "3. Add thorough input validation",
					description: "Even if your code is currently secure, add explicit input validation to protect against future changes."
				},
				{
					title: "4. Write unit tests",
					description: "Create unit tests to verify correctness and prevent regressions."
				}
			],
			isVulnerable: false
		};
	}
}

/**
 * Formats the HTML content for the improvement suggestions webview
 * @param suggestions The generated suggestions
 * @param result The original analysis result
 * @returns HTML content for the webview
 */
function getImprovementSuggestionsContent(
	suggestions: {
		title: string;
		description: string;
		suggestions: { title: string; description: string; code?: string }[];
		isVulnerable: boolean;
	},
	result: AnalysisResponse
): string {
	const statusStyle = suggestions.isVulnerable ?
		'color: #d73a49; background-color: rgba(255, 0, 0, 0.1); padding: 5px;' :
		'color: #22863a; background-color: rgba(0, 255, 0, 0.1); padding: 5px;';

	// Generate HTML for each suggestion
	const suggestionsHtml = suggestions.suggestions.map(suggestion => {
		const codeBlock = suggestion.code ?
			`<pre><code class="language-cpp">${escapeHtml(suggestion.code)}</code></pre>` :
			'';

		return `
			<div class="suggestion">
				<h3>${suggestion.title}</h3>
				<p>${suggestion.description}</p>
				${codeBlock}
			</div>
		`;
	}).join('');

	return `
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Suggestions for Improvement</title>
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
				h3 {
					margin-top: 20px;
					margin-bottom: 10px;
					font-weight: 600;
				}
				.status {
					font-weight: bold;
					display: inline-block;
					border-radius: 3px;
					${statusStyle}
				}
				.suggestion {
					background-color: #f8f9fa;
					border-left: 4px solid #0366d6;
					padding: 16px;
					margin-bottom: 20px;
					border-radius: 0 3px 3px 0;
				}
				pre {
					background-color: #f3f3f3;
					padding: 16px;
					border-radius: 3px;
					overflow-x: auto;
				}
				code {
					font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
					font-size: 0.9em;
				}
				.footer {
					margin-top: 40px;
					padding-top: 20px;
					border-top: 1px solid #eaecef;
					color: #586069;
					font-size: 0.9em;
				}
			</style>
		</head>
		<body>
			<h1>Suggestions for Improvement</h1>
			
			<h2>Code Status</h2>
			<div class="status">
				${suggestions.isVulnerable ? '⚠️ Vulnerable' : '✅ Benign'}
				${result.cweType ? ` - ${result.cweType}` : ''}
			</div>
			
			<h2>${suggestions.title}</h2>
			<p>${suggestions.description}</p>
			
			<div class="suggestions-container">
				${suggestionsHtml}
			</div>
			
			<div class="footer">
				<p>These suggestions are generated by an AI assistant based on static code analysis. 
				Always review and test changes thoroughly before implementing them in production code.</p>
			</div>
		</body>
		</html>
	`;
}

/**
 * Helper function to escape HTML special characters
 * @param text The text to escape
 * @returns Escaped text safe for HTML insertion
 */
function escapeHtml(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#039;");
}

// This method is called when your extension is deactivated
export function deactivate() {
	clearAllDecorations();
}

/**
 * Extract dependencies from code by making an API call
 * @param code The code to analyze
 * @param round The round number (starting from 1)
 * @returns Object containing dependencies array and done flag
 */
async function extractDependencies(code: string, round: number): Promise<ExtractResponse> {
	// Get the full API URL for extract endpoint
	const apiUrl = `${apiBaseUrl}/extract`;

	return new Promise((resolve, reject) => {
		const http = require('http');
		const urlObj = new URL(apiUrl);

		const options = {
			hostname: urlObj.hostname,
			port: urlObj.port || 80,
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
					const response: ExtractResult = JSON.parse(data);
					const result = response.result;

					if (response.status !== 'success') {
						// Fallback to default dependencies if the API doesn't return the expected format
						console.warn('API did not return expected format, using fallback dependencies');
						result.dependencies = getFallbackDependencies(round);
					}
					resolve(result);
				} catch (e) {
					console.error(`Failed to parse API response: ${e}`);
					reject(new Error(`Failed to parse API response: ${e}`));
				}
			});
		});

		req.on('error', (error: any) => {
			console.error(`API request failed: ${error.message}`);
			reject(new Error(`API request failed: ${error.message}`));
		});

		// Send the code and round information to the API
		const requestBody = JSON.stringify({
			code,
			round
		});
		req.write(requestBody);
		req.end();
	});
}

/**
 * Get fallback dependencies for a specific round if the API fails
 * @param round The extraction round
 * @returns Array of fallback dependencies
 */
function getFallbackDependencies(round: number): string[] {
	switch (round) {
		case 1:
			return ["font->ParseTable", "font->GetTable"];
		case 2:
			return ["GetTableData", "table->Parse", "AddTable"];
		case 3:
			return ["arena.Allocate"];
		case 4:
			return ["ParseTableData", "ValidateTable"];
		case 5:
			return ["CleanupMemory"];
		default:
			return [`Round ${round}: Unknown dependencies`];
	}
}

/**
 * CodeLens provider for showing vulnerability scan results
 */
class VulnerabilityScanCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

    constructor() {
        // Refresh CodeLenses when analysis results change
        const refreshCodeLenses = () => {
            this._onDidChangeCodeLenses.fire();
        };
        
        // Trigger refresh when configuration changes
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('vulscan')) {
                refreshCodeLenses();
            }
        });
    }

    public provideCodeLenses(document: vscode.TextDocument): vscode.ProviderResult<vscode.CodeLens[]> {
        // Get analysis results for this document
        const documentUri = document.uri.toString();
        const analysisResults = documentAnalysisResults.get(documentUri) || [];
        
        if (analysisResults.length === 0) {
            return [];
        }
        
        const codeLenses: vscode.CodeLens[] = [];
        
        // Create a CodeLens for each analyzed function
        for (const analysisResult of analysisResults) {
            const { functionSymbol, result } = analysisResult;
            
            // Create a range for the first line of the function
            const range = new vscode.Range(
                functionSymbol.range.start,
                functionSymbol.range.start.translate(0, functionSymbol.name.length + 2)
            );
            
            // Create CodeLens with appropriate title based on vulnerability status
            const title = result.status === VulnerabilityStatus.Vulnerable 
                ? `⚠️ Vulnerable: ${result.cweType || 'Unknown vulnerability'}`
                : '✅ Benign';
            
            // Command to show detailed explanation when clicked
            const command: vscode.Command = {
                title,
                command: 'vulscan.showFunctionDetails',
                arguments: [document.uri.toString(), functionSymbol.range.start.line, result]
            };
            
            codeLenses.push(new vscode.CodeLens(range, command));
        }
        
        return codeLenses;
    }
}

/**
 * Shows detailed explanation for a specific function
 * @param documentUri The URI of the document
 * @param line The line number of the function
 * @param result The analysis result
 */
async function showFunctionDetails(documentUri: string, line: number, result: AnalysisResponse): Promise<void> {
    // Set the last analysis result for the detailed explanation
    lastAnalysisResult = result;
    
    // Show the detailed explanation
    showDetailedExplanation();
}
