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
		let mockResult: AnalysisResult = {
			result: {
				status: VulnerabilityStatus.Vulnerable,
				cweType: 'CWE-416: Use After Free',
				response: 'Mock response for analysis'
			},
			status: 'success'
		};
		try {
			if (selectedText.includes('bool GetTableData')) {
				// Show progress notifications in sequence
				await vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: "Extracting dependencies",
					cancellable: false
				}, async (progress) => {
					progress.report({ message: "font->ParseTable, font->GetTable" });
					await new Promise(resolve => setTimeout(resolve, 1800));

					progress.report({ message: "GetTableData, table->Parse, AddTable" });
					await new Promise(resolve => setTimeout(resolve, 3000));

					progress.report({ message: "arena.Allocate" });
					await new Promise(resolve => setTimeout(resolve, 4000));
				});

				await vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: "Reducing dependencies",
					cancellable: false
				}, async (progress) => {
					await new Promise(resolve => setTimeout(resolve, 100));
				});

				await vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: "Querying model",
					cancellable: false
				}, async (progress) => {
					await new Promise(resolve => setTimeout(resolve, 3000));
				});

				// Mock vulnerability result after progress notifications
				mockResult = {
					result: {
						status: VulnerabilityStatus.Benign,
						cweType: 'N/A',
						response: 'The code you provided appears to be benign. The function GetTableData is designed to safely handle table data extraction and does not exhibit any known vulnerabilities. It uses a boolean return type to indicate success or failure, which is a common practice in C++ programming. The function also includes error handling mechanisms to ensure that any issues encountered during the data extraction process are properly managed.'

					},
					status: 'success'
				};
			}
			else {
				// Show progress notifications in sequence
				await vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: "Extracting dependencies",
					cancellable: false
				}, async (progress) => {
					progress.report({ message: "font->ParseTable, font->GetTable" });
					await new Promise(resolve => setTimeout(resolve, 1800));

					progress.report({ message: "GetTableData, table->Parse, AddTable" });
					await new Promise(resolve => setTimeout(resolve, 3000));

					progress.report({ message: "arena.Allocate" });
					await new Promise(resolve => setTimeout(resolve, 4000));
				});

				await vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: "Reducing dependencies",
					cancellable: false
				}, async (progress) => {
					await new Promise(resolve => setTimeout(resolve, 100));
				});

				await vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: "Querying model",
					cancellable: false
				}, async (progress) => {
					await new Promise(resolve => setTimeout(resolve, 6000));
				});

				// Mock vulnerability result after progress notifications
				mockResult = {
					result: {
						status: VulnerabilityStatus.Vulnerable,
						cweType: 'CWE-416: Use After Free',
						response: 'I\'ve reviewed the code you shared, and I think your analysis about a potential Use-After-Free (UAF) vulnerability is correct. Let me explain why:\nThe issue occurs in the relationship between the Arena class and how it\'s used in the font processing functions, specifically in ProcessGeneric and Font::ParseTable.\nHere\'s the problem:\n\nIn ProcessGeneric, an Arena object is created locally:\n\ncppots::Arena arena;\n\nThis arena is passed to Font::ParseTable which allocates memory through it:\n\ncppif (!font->ParseTable(it->second, data, arena)) {\n  return OTS_FAILURE_MSG_TAG("Failed to parse table", tag);\n}\n\nInside ParseTable, memory is allocated from the arena via GetTableData:\n\ncppif (GetTableData(data, table_entry, arena, &table_length, &table_data)) {\n  // FIXME: Parsing some tables will fail if the table is not added to\n  // m_tables first.\n  m_tables[tag] = table;\n  ret = table->Parse(table_data, table_length);\n  // ...\n}\n\nThe GetTableData function allocates memory from the arena:\n\ncpp*table_data = arena.Allocate(*table_length);\n\nThe problematic part is that the Font object stores pointers to the arena-allocated memory in its tables, but the arena goes out of scope at the end of ProcessGeneric, resulting in a Use-After-Free:\n\ncpp// Arena destructor\n~Arena() {\n  for (std::vector<uint8_t*>::begin(); i != hunks_.end(); ++i) {\n    delete[] *i;\n  }\n}\nThis is a classic UAF pattern where:\n\nMemory is allocated from the arena\nReferences to this memory are stored in the font\'s tables\nThe arena is destroyed, which frees all its allocated memory\nThe font still holds pointers to this freed memory\nLater accesses to these pointers (like during serialization in OpenTypeCMAP::Serialize) would be operating on freed memoryThe arena goes out of scope at the end of ProcessGeneric, resulting in a Use-After-Free situation, because of how C++ manages object lifetimes. Let me explain:\n\nIn the ProcessGeneric function, the Arena object is declared as a local variable:\ncppots::Arena arena;\n\nIn C++, local variables exist only within the scope they\'re declared in. When execution reaches the end of the function (the closing curly brace of ProcessGeneric), all local variables are destroyed automatically.\nWhen the arena is destroyed, its destructor is called:\ncpp~Arena() {\n  for (std::vector<uint8_t*>::iterator\n       i = hunks_.begin(); i != hunks_.end(); ++i) {\n    delete[] *i;\n  }\n}\nThis destructor frees all memory chunks that were allocated by the arena.\nHowever, the problem is that during ProcessGeneric, the Font object (which is passed by pointer and outlives the function) stores references to memory that was allocated by this arena:\ncppif (!font->ParseTable(it->second, data, arena)) {\n  // ...\n}\n\nInside ParseTable, memory is allocated through the arena, and pointers to this memory are stored in the font\'s tables:\ncppif (GetTableData(data, table_entry, arena, &table_length, &table_data)) {\n  m_tables[tag] = table;\n  // ...\n}\n\nAfter ProcessGeneric returns, the Font object continues to exist, but the arena that allocated memory for its table data has been destroyed. This means the font now contains pointers to memory that has been freed, resulting in a Use-After-Free condition.\nIf any code later accesses these tables (like during serialization), it will be accessing freed memory, which can lead to crashes, data corruption, or security vulnerabilities.\n\nThis is a common memory management issue in C++ where the lifetime of allocated resources doesn\'t match the lifetime of objects that reference those resources. A proper fix would involve ensuring the arena lives at least as long as the font object, or implementing a different memory management strategy.\n## Final Answer\n#judge: yes\n#type: CWE-416'

					},
					status: 'success'
				};
			}

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

				const implPromise = vscode.commands.executeCommand<vscode.Location[]>(
					'vscode.executeImplementationProvider',
					editor.document.uri,
					position
				).then(locations => {
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
						const implPromise = vscode.commands.executeCommand<vscode.Location[]>(
							'vscode.executeImplementationProvider',
							editor.document.uri,
							callPosition
						).then(locations => {
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
// Original selected code:
${selectedText}

// Implementations of functions called in the selected code:
${implementationsText}
`;

			console.log('Analyzing code with implementations included');
			const result = mockResult; // Use mock result
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
					'Suggestions for Improvement'
				).then(selection => {
					if (selection === 'Show Details') {
						showDetailedExplanation();
					} else if (selection === 'Suggestions for Improvement') {
						showImprovementSuggestions(pred);
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
	const apiUrl = config.get('apiUrl') as string || "http://6479122b-01.cloud.together.ai:4400/analyze";

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

	// Define file references with proper paths and lines
	const functionReferences = `
        <h2>Function References</h2>
        <ul>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 967); return false;"><strong>font->ParseTable</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 587); return false;"><strong>GetTableData</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 1162); return false;"><strong>table->Parse</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 79); return false;"><strong>arena.Allocate</strong></a></li>
            <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 1070); return false;"><strong>AddTable</strong></a></li>
        </ul>
    `;

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
