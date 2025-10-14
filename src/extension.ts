import * as vscode from 'vscode';
import {
	EUAIActViolationStatus,
	EUAIActAnalysisResponse,
	analyzeCodeForEUAIAct,
	getEUAIActDecorationForResult,
	showEUAIActDetailedExplanation,
	showEUAIActFunctionDetails
} from './euaiact';
import {
	AnalysisResponse,
	VulnerabilityStatus,
	analyzeCodeForVulnerabilities,
	extractDependencies,
	checkTokenUsage
} from './apiService';
import {
	analyzeDocumentOnSave,
	getDocumentSymbols
} from './analysisManager';
import {
	clearAllDecorations,
	getDecorationForResult,
	refreshDecorations,
	showDetailedExplanation,
	VulnerabilityScanCodeLensProvider,
	showFunctionDetails,
	setLastAnalysisResult,
	saveManualDecoration
} from './uiManager';

// Import interfaces from apiService

// Import from analysisManager

// Define a global API base URL
let apiBaseUrl: string = "https://api.virtueai.io/api/vulscan";

// Store the selected model
let selectedModel: string = "virtueguard-code";

// Store single API key
let apiKey: string = "";

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
			await analyzeDocumentOnSave(document, apiBaseUrl, selectedModel, getCurrentApiKey(), getDecorationForResult, clearAllDecorations, refreshDecorations);
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
					const result = await extractDependencies(selectedText, round, apiBaseUrl, selectedModel, getCurrentApiKey());

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
				const result = await analyzeCodeForVulnerabilities(
					codeToAnalyze,
					editor.document.languageId,
					apiBaseUrl,
					selectedModel,
					getCurrentApiKey(),
					vscode.workspace.asRelativePath(editor.document.uri.fsPath),
					selection.start.line + 1, // Convert to 1-based line numbering
					selection.end.line + 1 // Convert to 1-based line numbering
				);
				const pred = result.result;
				setLastAnalysisResult(pred); // Store for detailed explanation
				const decorationType = getDecorationForResult(pred);

				editor.setDecorations(decorationType, [selection]);

				// Save the manual decoration for later restoration when switching files
				saveManualDecoration(editor.document.uri.toString(), selection, pred);

				// Display the result with a button for detailed explanation
				if (pred.status === VulnerabilityStatus.Vulnerable) {
					vscode.window.showErrorMessage(
						`Vulnerability detected: ${pred.cweType}`,
						{ modal: false },
						'Show Details'
					).then(userSelection => {
						if (userSelection === 'Show Details') {
							showDetailedExplanation();
						}
					});
				} else {
					vscode.window.showInformationMessage(
						'Code appears to be benign',
						{ modal: false },
						'Show Details'
					).then(userSelection => {
						if (userSelection === 'Show Details') {
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

				const result = await analyzeCodeForEUAIAct(
					codeToAnalyze,
					apiBaseUrl,
					selectedModel,
					getCurrentApiKey(),
					editor.document.uri.fsPath,
					selection.start.line + 1, // Convert to 1-based line numbering
					selection.end.line + 1 // Convert to 1-based line numbering
				);
				const pred = result.result;

				const decorationType = getEUAIActDecorationForResult(pred, []);
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
				const tokenUsage = await checkTokenUsage(apiBaseUrl, getCurrentApiKey());

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


	// Listen for active text editor changes to refresh decorations
	const onDidChangeActiveTextEditor = vscode.window.onDidChangeActiveTextEditor((editor) => {
		if (editor) {
			console.log(`Active editor changed to: ${editor.document.fileName}`);
			// Refresh decorations for the newly active editor
			// This ensures that if analysis was completed while the user was viewing another file,
			// decorations will be applied when they return to this file
			refreshDecorations(editor);
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
		onDidChangeActiveTextEditor,
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
 * Save API key to VS Code configuration
 */
async function saveApiKeyToConfig(): Promise<void> {
	const config = vscode.workspace.getConfiguration('vulscan');
	await config.update('apiKey', apiKey, vscode.ConfigurationTarget.Global);
}

// This method is called when your extension is deactivated
export function deactivate() {
	clearAllDecorations();
}