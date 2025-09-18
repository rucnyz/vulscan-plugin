import * as vscode from 'vscode';
import { AnalysisResponse, VulnerabilityStatus } from './apiService';
import { EUAIActAnalysisResponse, EUAIActViolationStatus, getEUAIActDecorationForResult } from './euaiact';
import {
	documentAnalysisResults,
	documentEUAIActResults,
	FunctionAnalysisResult,
	FunctionEUAIActResult,
	getAnalysisResults,
	getEUAIActResults
} from './analysisManager';

// Track active decorations
let activeDecorations: vscode.TextEditorDecorationType[] = [];

// Store the latest analysis result for showing detailed explanation
let lastAnalysisResult: AnalysisResponse | null = null;

/**
 * Clear all active decorations
 */
export function clearAllDecorations() {
	activeDecorations.forEach(decoration => {
		decoration.dispose();
	});
	activeDecorations = [];
}

/**
 * Get the appropriate decoration type based on analysis result
 */
export function getDecorationForResult(result: AnalysisResponse): vscode.TextEditorDecorationType {
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
 * Refresh decorations for a specific editor based on stored analysis results
 * @param editor The text editor to refresh decorations for
 */
export function refreshDecorations(editor: vscode.TextEditor) {
	const documentUri = editor.document.uri.toString();
	const analysisResults = getAnalysisResults(documentUri);
	const euAIActResults = getEUAIActResults(documentUri);

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
 * Shows detailed explanation of the last analysis result in a read-only editor
 */
export function showDetailedExplanation() {
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
                    color: var(--vscode-foreground);
                    background-color: var(--vscode-editor-background);
                }
                h1 {
                    border-bottom: 1px solid var(--vscode-panel-border);
                    padding-bottom: 10px;
                    margin-bottom: 20px;
                    color: var(--vscode-foreground);
                }
                h2 {
                    margin-top: 24px;
                    margin-bottom: 16px;
                    font-weight: 600;
                    color: var(--vscode-foreground);
                }
                .status {
                    font-weight: bold;
                    display: inline-block;
                    border-radius: 3px;
                    ${statusStyle}
                }
                .explanation {
                    background-color: var(--vscode-textBlockQuote-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 3px;
                    padding: 16px;
                    color: var(--vscode-foreground);
                }
                pre {
                    background-color: var(--vscode-textPreformat-background);
                    border: 1px solid var(--vscode-panel-border);
                    padding: 10px;
                    border-radius: 3px;
                    overflow-x: auto;
                    color: var(--vscode-foreground);
                }
                code {
                    font-family: var(--vscode-editor-font-family);
                    font-size: 0.9em;
                    background-color: var(--vscode-textPreformat-background);
                    padding: 1px 3px;
                    border-radius: 3px;
                    color: var(--vscode-foreground);
                }
                blockquote {
                    border-left: 4px solid var(--vscode-textBlockQuote-border);
                    padding-left: 16px;
                    margin-left: 0;
                    color: var(--vscode-foreground);
                    background-color: var(--vscode-textBlockQuote-background);
                }
                ul {
                    padding-left: 20px;
                }
                li {
                    margin-bottom: 8px;
                    color: var(--vscode-foreground);
                }
                a {
                    color: var(--vscode-textLink-foreground);
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                    color: var(--vscode-textLink-activeForeground);
                }
                .function-ref {
                    font-family: var(--vscode-editor-font-family);
                    background-color: var(--vscode-textPreformat-background);
                    padding: 2px 4px;
                    border-radius: 3px;
                    color: var(--vscode-foreground);
                }
                p {
                    color: var(--vscode-foreground);
                }
                strong {
                    color: var(--vscode-foreground);
                }
                em {
                    color: var(--vscode-foreground);
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
 * CodeLens provider for showing vulnerability scan results
 */
export class VulnerabilityScanCodeLensProvider implements vscode.CodeLensProvider {
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
		const analysisResults = getAnalysisResults(documentUri);
		const euAIActResults = getEUAIActResults(documentUri);

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
export async function showFunctionDetails(documentUri: string, line: number, result: AnalysisResponse): Promise<void> {
	// Set the last analysis result for the detailed explanation
	lastAnalysisResult = result;

	// Show the detailed explanation
	showDetailedExplanation();
}

/**
 * Set the last analysis result for detailed explanation
 * @param result The analysis result
 */
export function setLastAnalysisResult(result: AnalysisResponse): void {
	lastAnalysisResult = result;
}