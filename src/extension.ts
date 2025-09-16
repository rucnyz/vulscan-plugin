import * as vscode from 'vscode';
import {
	EUAIActViolationStatus,
	EUAIActAnalysisResponse,
	documentEUAIActResults,
	analyzeCodeForEUAIAct,
	getEUAIActDecorationForResult,
	showEUAIActDetailedExplanation,
	showEUAIActFunctionDetails,
	getDocumentSymbols as getDocumentSymbols
} from './euaiact';

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

interface TokenUsageResponse {
	tokens_used: number;
	token_limit: number;
	usage_percentage: number;
	is_near_limit: boolean;
}

// Track active decorations
let activeDecorations: vscode.TextEditorDecorationType[] = [];

// Store the latest analysis result for showing detailed explanation
let lastAnalysisResult: AnalysisResponse | null = null;

// Define a global API base URL
let apiBaseUrl: string = "https://api.virtueai.io/api/vulscan";

// Store the selected model
let selectedModel: string = "virtueguard-code";

// Get current API key
function getCurrentApiKey(): string {
	return apiKey;
}

// Export for testing
export function setApiKeyForTesting(key: string) {
	apiKey = key;
	// Save to config to maintain consistency
	saveApiKeyToConfig();
}

// Store single API key
let apiKey: string = "";





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
	// Get API base URL, model, and API key from configuration
	const config = vscode.workspace.getConfiguration('vulscan');
	apiBaseUrl = config.get('apiBaseUrl') as string || apiBaseUrl;
	selectedModel = config.get('selectedModel') as string || 'virtueguard-code';
	apiKey = config.get('apiKey') as string || "";

	console.log(`Using API base URL: ${apiBaseUrl}`);
	console.log(`Using model: ${selectedModel}`);
	console.log(`API key configured: ${apiKey ? 'Yes' : 'No'}`);

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
			// Check if API key is configured
			if (!getCurrentApiKey()) {
				vscode.window.showWarningMessage('Auto-analysis disabled: API key is required. Please add an API key using the command palette.');
				return;
			}
			await analyzeDocumentOnSave(document);
		}
	});

	// Register a command to analyze selected code for vulnerabilities
	const analyzeCodeCommand = vscode.commands.registerCommand('vulscan.analyzeCode', async () => {
		// Check if API key is configured
		if (!getCurrentApiKey()) {
			vscode.window.showErrorMessage('API key is required. Please add an API key using the command palette.');
			return;
		}

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
				const maxRounds = 5;

				while (!isDone && round <= maxRounds) {
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

				if (round > maxRounds && !isDone) {
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
				const result = await analyzeCodeForVulnerabilities(codeToAnalyze, editor.document.languageId);
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
			});
		} catch (error) {
			vscode.window.showErrorMessage(`Error analyzing code: ${error}`);
		}
	});

	// Register a command to analyze selected code for EU AI Act compliance
	const analyzeEUAIActCommand = vscode.commands.registerCommand('vulscan.analyzeEUAIAct', async () => {
		// Check if API key is configured
		if (!getCurrentApiKey()) {
			vscode.window.showErrorMessage('API key is required. Please add an API key using the command palette.');
			return;
		}

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
		vscode.window.showInformationMessage('Analyzing code for EU AI Act compliance...');

		try {
			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: "Analyzing EU AI Act compliance",
				cancellable: false
			}, async (progress) => {
				// Gather implementations similar to vulnerability analysis
				const implementationsPromises: Promise<string>[] = [];
				const symbols = await getDocumentSymbols(editor.document);

				const symbolsInSelection = symbols.filter(symbol =>
					selection.contains(symbol.range) ||
					symbol.range.contains(selection) ||
					selection.intersection(symbol.range)
				);

				// Get implementations
				for (const symbol of symbolsInSelection) {
					const position = symbol.selectionRange.start;
					const implPromise = (vscode.commands.executeCommand<vscode.Location[]>(
						'vscode.executeImplementationProvider',
						editor.document.uri,
						position
					) as Promise<vscode.Location[]>).then(locations => {
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

				const implementations = await Promise.all(implementationsPromises);
				const implementationsText = implementations.filter(impl => impl.length > 0).join('\n\n');

				const codeToAnalyze = `
// Context
${implementationsText}
// Original selected code
${selectedText}
`;

				const result = await analyzeCodeForEUAIAct(codeToAnalyze, apiBaseUrl, selectedModel, getCurrentApiKey());
				const pred = result.result;

				const decorationType = getEUAIActDecorationForResult(pred, activeDecorations);
				editor.setDecorations(decorationType, [selection]);

				// Display the result
				if (pred.status === EUAIActViolationStatus.Violation) {
					vscode.window.showErrorMessage(
						`EU AI Act Violation: ${pred.article}`,
						{ modal: false },
						'Show Details'
					).then(selection => {
						if (selection === 'Show Details') {
							showEUAIActDetailedExplanation();
						}
					});
				} else {
					vscode.window.showInformationMessage(
						'No EU AI Act violations detected',
						{ modal: false },
						'Show Details'
					).then(selection => {
						if (selection === 'Show Details') {
							showEUAIActDetailedExplanation();
						}
					});
				}
			});
		} catch (error) {
			vscode.window.showErrorMessage(`Error analyzing code for EU AI Act: ${error}`);
		}
	});

	// Register a command to clear all decorations
	const clearDecorations = vscode.commands.registerCommand('vulscan.clearDecorations', () => {
		clearAllDecorations();
	});

	// Register a command to show detailed explanation
	const showDetailsCommand = vscode.commands.registerCommand('vulscan.showDetails', () => {
		showDetailedExplanation();
	});

	// Register a command to show EU AI Act details
	const showEUAIActDetailsCommand = vscode.commands.registerCommand('vulscan.showEUAIActDetails', () => {
		showEUAIActDetailedExplanation();
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

	// Register a command to select the model
	const selectModelCommand = vscode.commands.registerCommand('vulscan.selectModel', async () => {
		const models = [
			{ label: 'VirtueGuard-Code', value: 'virtueguard-code', description: 'Optimized for security vulnerability detection' },
			{ label: 'Claude 4 Sonnet', value: 'claude-4-sonnet', description: 'Advanced AI model for comprehensive code analysis' }
		];

		const selected = await vscode.window.showQuickPick(models, {
			placeHolder: 'Select an AI model for vulnerability analysis',
			canPickMany: false
		});

		if (selected) {
			const config = vscode.workspace.getConfiguration('vulscan');
			await config.update('selectedModel', selected.value, vscode.ConfigurationTarget.Global);
			selectedModel = selected.value;
			vscode.window.showInformationMessage(`Model switched to: ${selected.label}`);
		}
	});


	// Register command to open API key settings
	const openApiKeySettingsCommand = vscode.commands.registerCommand('vulscan.openApiKeySettings', () => {
		vscode.commands.executeCommand('workbench.action.openSettings', 'vulscan.apiKey');
	});

	// Register command to check token usage
	const checkTokenUsageCommand = vscode.commands.registerCommand('vulscan.checkTokenUsage', async () => {
		// Check if API key is configured
		if (!getCurrentApiKey()) {
			vscode.window.showErrorMessage('API key is required to check token usage.');
			return;
		}

		try {
			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: "Checking token usage",
				cancellable: false
			}, async (progress) => {
				const tokenUsage = await checkTokenUsageInternal();

				// Display the token usage information
				const message = `Token usage: ${tokenUsage.tokens_used}/${tokenUsage.token_limit} (${tokenUsage.usage_percentage}%)`;

				if (tokenUsage.is_near_limit) {
					vscode.window.showWarningMessage(`${message}\n⚠️ Approaching token limit!`);
				} else {
					vscode.window.showInformationMessage(message);
				}
			});
		} catch (error) {
			vscode.window.showErrorMessage(`Failed to check token usage: ${error}`);
		}
	});


	// Listen for configuration changes
	const configListener = vscode.workspace.onDidChangeConfiguration((e) => {
		if (e.affectsConfiguration('vulscan.autoAnalyzeOnSave')) {
			const config = vscode.workspace.getConfiguration('vulscan');
			const autoAnalyzeOnSave = config.get('autoAnalyzeOnSave') as boolean || false;
			console.log(`Configuration changed: Auto-analyze on save: ${autoAnalyzeOnSave}`);
		}

		// Update API base URL when configuration changes
		if (e.affectsConfiguration('vulscan.apiBaseUrl')) {
			const config = vscode.workspace.getConfiguration('vulscan');
			const newApiUrl = config.get('apiBaseUrl') as string;
			if (newApiUrl && newApiUrl !== apiBaseUrl) {
				apiBaseUrl = newApiUrl;
				console.log(`Configuration changed: API base URL updated to: ${apiBaseUrl}`);
			}
		}

		// Update selected model when configuration changes
		if (e.affectsConfiguration('vulscan.selectedModel')) {
			const config = vscode.workspace.getConfiguration('vulscan');
			const newModel = config.get('selectedModel') as string;
			if (newModel && newModel !== selectedModel) {
				selectedModel = newModel;
				console.log(`Configuration changed: Model updated to: ${selectedModel}`);
			}
		}

		// Update API key when configuration changes
		if (e.affectsConfiguration('vulscan.apiKey')) {
			const config = vscode.workspace.getConfiguration('vulscan');
			apiKey = config.get('apiKey') as string || "";

			console.log(`Configuration changed: API key configured: ${apiKey ? 'Yes' : 'No'}`);
		}
	});

	// Add all subscriptions
	context.subscriptions.push(
		analyzeCodeCommand,
		analyzeEUAIActCommand,
		clearDecorations,
		onSaveListener,
		showDetailsCommand,
		showEUAIActDetailsCommand,
		toggleAutoAnalyzeCommand,
		selectModelCommand,
		openApiKeySettingsCommand,
		checkTokenUsageCommand,
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

	// Register command to show EU AI Act function details from CodeLens
	const showEUAIActFunctionDetailsCommand = vscode.commands.registerCommand(
		'vulscan.showEUAIActFunctionDetails',
		(documentUri: string, line: number, result: EUAIActAnalysisResponse) => {
			showEUAIActFunctionDetails(documentUri, line, result);
		}
	);

	// Add commands to subscriptions
	context.subscriptions.push(showFunctionDetailsCommand);
	context.subscriptions.push(showEUAIActFunctionDetailsCommand);
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
 * Refresh decorations for a specific editor based on stored analysis results
 * @param editor The text editor to refresh decorations for
 */
function refreshDecorations(editor: vscode.TextEditor) {
	const documentUri = editor.document.uri.toString();
	const analysisResults = documentAnalysisResults.get(documentUri) || [];
	const euAIActResults = documentEUAIActResults.get(documentUri) || [];

	// Clear existing decorations for this editor first
	const editorDecorations = activeDecorations.slice();
	editorDecorations.forEach(decoration => {
		editor.setDecorations(decoration, []);
	});

	// Reapply vulnerability decorations based on stored results
	for (const analysisResult of analysisResults) {
		const { functionSymbol, result } = analysisResult;

		// Only add decoration for vulnerable functions
		if (result.status === VulnerabilityStatus.Vulnerable) {
			const decorationType = getDecorationForResult(result);
			editor.setDecorations(decorationType, [functionSymbol.range]);
		}
	}

	// Reapply EU AI Act decorations based on stored results
	for (const euAIActResult of euAIActResults) {
		const { functionSymbol, result } = euAIActResult;

		// Add decoration for EU AI Act violations
		if (result.status === EUAIActViolationStatus.Violation) {
			const decorationType = getEUAIActDecorationForResult(result, activeDecorations);
			editor.setDecorations(decorationType, [functionSymbol.range]);
		}
	}
}

/**
 * Save API key to VS Code configuration
 */
async function saveApiKeyToConfig(): Promise<void> {
	const config = vscode.workspace.getConfiguration('vulscan');
	await config.update('apiKey', apiKey, vscode.ConfigurationTarget.Global);
}






/**
 * Make API request with basic error handling
 * @param makeRequest Function to make the API request
 * @returns Promise with the API result
 */
async function makeRequestWithRetry<T>(
	makeRequest: () => Promise<T>
): Promise<T> {
	try {
		return await makeRequest();
	} catch (error: any) {
		// Token limit errors should be thrown immediately for user attention
		throw error;
	}
}

/**
 * Internal function to make vulnerability analysis request
 * @param code The code to analyze
 * @param languageId The programming language identifier
 * @returns Analysis result
 */
async function analyzeCodeForVulnerabilitiesInternal(code: string, languageId: string): Promise<AnalysisResult> {
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
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${getCurrentApiKey()}`,
				'X-API-Key': getCurrentApiKey()
			}
		};

		const req = http.request(options, (res: any) => {
			let data = '';

			// Handle 403 Forbidden (likely token limit exceeded)
			if (res.statusCode === 403) {
				// Try to get error details from response body
				let errorData = '';
				res.on('data', (chunk: any) => {
					errorData += chunk;
				});
				res.on('end', () => {
					try {
						const errorResponse = JSON.parse(errorData);
						const errorMessage = errorResponse.detail || 'Token limit exceeded. Please check your API key quota.';
						vscode.window.showErrorMessage(errorMessage);
						return reject(new Error(errorMessage));
					} catch (e) {
						const errorMessage = 'Token limit exceeded. Please check your API key quota.';
						vscode.window.showErrorMessage(errorMessage);
						return reject(new Error(errorMessage));
					}
				});
				return; // Don't continue processing
			}

			// Handle other HTTP status errors
			if (res.statusCode < 200 || res.statusCode >= 300) {
				// Try to get error details from response body
				let errorData = '';
				res.on('data', (chunk: any) => {
					errorData += chunk;
				});
				res.on('end', () => {
					try {
						const errorResponse = JSON.parse(errorData);
						const errorMessage = errorResponse.detail || `API responded with status code ${res.statusCode}`;
						vscode.window.showErrorMessage(errorMessage);
						return reject(new Error(errorMessage));
					} catch (e) {
						const errorMessage = `API responded with status code ${res.statusCode}`;
						vscode.window.showErrorMessage(errorMessage);
						return reject(new Error(errorMessage));
					}
				});
				return; // Don't continue processing
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

		// Send the code, model, and language to analyze
		const requestBody = JSON.stringify({ code, model: selectedModel, language: languageId });
		req.write(requestBody);
		req.end();
	});
}

/**
 * Send the code to an API for vulnerability analysis
 * @param code The code to analyze
 * @param languageId The programming language identifier
 * @returns Analysis result
 */
async function analyzeCodeForVulnerabilities(code: string, languageId: string): Promise<AnalysisResult> {
	return await makeRequestWithRetry(() => analyzeCodeForVulnerabilitiesInternal(code, languageId));
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
	// if (result.cweType === 'CWE-416') {
	// 	functionReferences = `
	//     <h2>Function References</h2>
	//     <ul>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 967); return false;"><strong>font->ParseTable</strong></a></li>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 587); return false;"><strong>GetTableData</strong></a></li>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 1162); return false;"><strong>table->Parse</strong></a></li>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 79); return false;"><strong>arena.Allocate</strong></a></li>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/ots/src/ots.cc', 1070); return false;"><strong>AddTable</strong></a></li>
	//     </ul>
	// `;
	// }
	// else if (result.cweType === 'CWE-200'){
	// 	functionReferences = `
	//     <h2>Function References</h2>
	//     <ul>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/server/middlewares/static.ts', 264); return false;"><strong>ensureServingAccess</strong></a></li>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 353); return false;"><strong>rawRE</strong></a></li>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 352); return false;"><strong>urlRE</strong></a></li>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/server/middlewares/static.ts', 223); return false;"><strong>isFileServingAllowed</strong></a></li>
	//         <li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 269); return false;"><strong>fsPathFromUrl</strong></a></li>
	// 		<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 262); return false;"><strong>fsPathFromId</strong></a></li>
	// 		<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/shared/utils.ts', 31); return false;"><strong>cleanUrl</strong></a></li>
	// 		<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 256); return false;"><strong>VOLUME_RE</strong></a></li>			
	// 		<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/shared/utils.ts', 30); return false;"><strong>postfixRE</strong></a></li>
	// 		<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/utils.ts', 258); return false;"><strong>normalizePath</strong></a></li>			
	// 		<li><a href="javascript:void(0)" onclick="openFile('C:/Users/yuzhounie/OneDrive - purdue.edu/PycharmProjects/plugins/examples/vite/packages/vite/src/node/server/middlewares/static.ts', 247); return false;"><strong>isFileLoadingAllowed</strong></a></li>
	//     </ul>
	// `;
	// }


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
				symbol.kind === vscode.SymbolKind.Constructor)
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
						? analyzeCodeForVulnerabilities(functionCode, document.languageId)
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

		// Refresh decorations after progress completes to ensure they are visible
		setTimeout(() => {
			refreshDecorations(editor);
		}, 100);

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






// This method is called when your extension is deactivated
export function deactivate() {
	clearAllDecorations();
}

/**
 * Internal function to extract dependencies from code
 * @param code The code to analyze
 * @param round The round number (starting from 1)
 * @returns Object containing dependencies array and done flag
 */
async function extractDependenciesInternal(code: string, round: number): Promise<ExtractResponse> {
	// Get the full API URL for extract endpoint
	const apiUrl = `${apiBaseUrl}/extract`;

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
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${getCurrentApiKey()}`,
				'X-API-Key': getCurrentApiKey()
			}
		};

		const req = http.request(options, (res: any) => {
			let data = '';

			// Handle 403 Forbidden (likely token limit exceeded)
			if (res.statusCode === 403) {
				// Try to get error details from response body
				let errorData = '';
				res.on('data', (chunk: any) => {
					errorData += chunk;
				});
				res.on('end', () => {
					try {
						const errorResponse = JSON.parse(errorData);
						const errorMessage = errorResponse.detail || 'Token limit exceeded. Please check your API key quota.';
						vscode.window.showErrorMessage(errorMessage);
						return reject(new Error(errorMessage));
					} catch (e) {
						const errorMessage = 'Token limit exceeded. Please check your API key quota.';
						vscode.window.showErrorMessage(errorMessage);
						return reject(new Error(errorMessage));
					}
				});
				return; // Don't continue processing
			}

			// Handle other HTTP status errors
			if (res.statusCode < 200 || res.statusCode >= 300) {
				// Try to get error details from response body
				let errorData = '';
				res.on('data', (chunk: any) => {
					errorData += chunk;
				});
				res.on('end', () => {
					try {
						const errorResponse = JSON.parse(errorData);
						const errorMessage = errorResponse.detail || `API responded with status code ${res.statusCode}`;
						vscode.window.showErrorMessage(errorMessage);
						return reject(new Error(errorMessage));
					} catch (e) {
						const errorMessage = `API responded with status code ${res.statusCode}`;
						vscode.window.showErrorMessage(errorMessage);
						return reject(new Error(errorMessage));
					}
				});
				return; // Don't continue processing
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
						result.dependencies = [];
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

		// Send the code, round, and model information to the API
		const requestBody = JSON.stringify({
			code,
			round,
			model: selectedModel
		});
		req.write(requestBody);
		req.end();
	});
}

/**
 * Extract dependencies from code by making an API call
 * @param code The code to analyze
 * @param round The round number (starting from 1)
 * @returns Object containing dependencies array and done flag
 */
async function extractDependencies(code: string, round: number): Promise<ExtractResponse> {
	return await makeRequestWithRetry(() => extractDependenciesInternal(code, round));
}

/**
 * Internal function to check token usage
 * @returns Token usage information
 */
async function checkTokenUsageInternal(): Promise<TokenUsageResponse> {
	// Get the full API URL for token usage endpoint
	const apiUrl = `${apiBaseUrl}/my-token-usage`;

	return new Promise((resolve, reject) => {
		// Parse URL to determine if http or https should be used
		const isHttps = apiUrl.startsWith('https');
		const http = isHttps ? require('https') : require('http');
		const urlObj = new URL(apiUrl);

		const options = {
			hostname: urlObj.hostname,
			port: urlObj.port || (isHttps ? 443 : 80),
			path: urlObj.pathname,
			method: 'GET',
			headers: {
				'X-API-Key': getCurrentApiKey()
			}
		};

		const req = http.request(options, (res: any) => {
			let data = '';

			// Handle HTTP status errors
			if (res.statusCode < 200 || res.statusCode >= 300) {
				let errorData = '';
				res.on('data', (chunk: any) => {
					errorData += chunk;
				});
				res.on('end', () => {
					try {
						const errorResponse = JSON.parse(errorData);
						let errorMessage = errorResponse.detail || `API responded with status code ${res.statusCode}`;

						// Handle specific 404 error for API key not found
						if (res.statusCode === 404) {
							errorMessage = 'API key not found. Please check your API key configuration.';
						}

						return reject(new Error(errorMessage));
					} catch (e) {
						let errorMessage = `API responded with status code ${res.statusCode}`;

						// Handle specific 404 error for API key not found
						if (res.statusCode === 404) {
							errorMessage = 'API key not found. Please check your API key configuration.';
						}

						return reject(new Error(errorMessage));
					}
				});
				return;
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

		req.end();
	});
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
		const euAIActResults = documentEUAIActResults.get(documentUri) || [];

		if (analysisResults.length === 0 && euAIActResults.length === 0) {
			return [];
		}

		const codeLenses: vscode.CodeLens[] = [];

		// Create a CodeLens for each analyzed function (vulnerability analysis)
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

		// Create CodeLens for EU AI Act results
		for (const euAIActResult of euAIActResults) {
			const { functionSymbol, result } = euAIActResult;

			// Create a range for the function (slightly offset from vulnerability lens)
			const range = new vscode.Range(
				functionSymbol.range.start.translate(1, 0),
				functionSymbol.range.start.translate(1, functionSymbol.name.length + 2)
			);

			// Create CodeLens with EU AI Act status
			const title = result.status === EUAIActViolationStatus.Violation
				? `🇪🇺 EU AI Act Violation: ${result.article || 'Unknown violation'}`
				: '🇪🇺 EU AI Act Compliant';

			// Command to show EU AI Act details when clicked
			const command: vscode.Command = {
				title,
				command: 'vulscan.showEUAIActFunctionDetails',
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


