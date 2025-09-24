import * as vscode from 'vscode';
import { AnalysisResponse, VulnerabilityStatus, analyzeCodeForVulnerabilities, AnalysisResult } from './apiService';
import { EUAIActAnalysisResponse } from './euaiact';

// Store analysis results by function/method
export interface FunctionAnalysisResult {
	functionSymbol: vscode.DocumentSymbol;
	result: AnalysisResponse;
	codeHash: string; // Add this field to track code changes
	model: string; // Add this field to track which model was used
}

// EU AI Act analysis result
export interface FunctionEUAIActResult {
	functionSymbol: vscode.DocumentSymbol;
	result: EUAIActAnalysisResponse;
	codeHash: string;
	model: string; // Add this field to track which model was used
}

// Map to store analysis results by document URI
export const documentAnalysisResults = new Map<string, FunctionAnalysisResult[]>();
export const documentEUAIActResults = new Map<string, FunctionEUAIActResult[]>();

/**
 * Generates a simple hash of code content to detect changes
 * @param code The code to hash
 * @returns A string hash representation
 */
export function generateCodeHash(code: string): string {
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
 * Get document symbols helper function
 * @param document The document to get symbols from
 * @returns Array of document symbols
 */
export async function getDocumentSymbols(document: vscode.TextDocument): Promise<vscode.DocumentSymbol[]> {
	const symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>(
		'vscode.executeDocumentSymbolProvider',
		document.uri
	);
	return symbols || [];
}

/**
 * Analyzes the entire document or code chunks when a file is saved
 * @param document The document that was saved
 * @param apiBaseUrl The API base URL
 * @param selectedModel The model to use
 * @param apiKey The API key
 * @param getDecorationForResult Function to get decoration for result
 */
export async function analyzeDocumentOnSave(
	document: vscode.TextDocument,
	apiBaseUrl: string,
	selectedModel: string,
	apiKey: string,
	getDecorationForResult: (result: AnalysisResponse) => vscode.TextEditorDecorationType,
	clearAllDecorations: () => void,
	refreshDecorations: (editor: vscode.TextEditor) => void
): Promise<void> {
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

				// Check if we already have a result for this function with the same hash and model
				const existingResult = currentResults.find(r =>
					r.functionSymbol.name === functionSymbol.name &&
					r.codeHash === codeHash &&
					r.model === selectedModel
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
						? analyzeCodeForVulnerabilities(
							functionCode,
							document.languageId,
							apiBaseUrl,
							selectedModel,
							apiKey,
							vscode.workspace.asRelativePath(document.uri.fsPath),
							functionSymbol.range.start.line + 1, // Convert to 1-based line numbering
							functionSymbol.range.end.line + 1 // Convert to 1-based line numbering
						)
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
						// Create the analysis result object with code hash and model
						const analysisResult = {
							functionSymbol: item.functionSymbol,
							result: result.result,
							codeHash: item.codeHash,
							model: selectedModel
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
 * Clear analysis results for a specific document
 * @param documentUri The document URI
 */
export function clearAnalysisResults(documentUri: string): void {
	documentAnalysisResults.delete(documentUri);
	documentEUAIActResults.delete(documentUri);
}

/**
 * Get analysis results for a specific document
 * @param documentUri The document URI
 * @returns Analysis results
 */
export function getAnalysisResults(documentUri: string): FunctionAnalysisResult[] {
	return documentAnalysisResults.get(documentUri) || [];
}

/**
 * Get EU AI Act analysis results for a specific document
 * @param documentUri The document URI
 * @returns EU AI Act analysis results
 */
export function getEUAIActResults(documentUri: string): FunctionEUAIActResult[] {
	return documentEUAIActResults.get(documentUri) || [];
}