import * as vscode from 'vscode';

// Define enum for EU AI Act violation status
export enum EUAIActViolationStatus {
	NoViolation = 'no',
	Violation = 'yes'
}

// Define interfaces for EU AI Act analysis
export interface EUAIActAnalysisResponse {
	status: EUAIActViolationStatus;
	violationType?: string;
	article?: string;
	model?: string;
	response?: string;
	usage?: any;
}

export interface EUAIActAnalysisResult {
	result: EUAIActAnalysisResponse;
	status: 'success' | 'error';
}

export interface FunctionEUAIActResult {
	functionSymbol: vscode.DocumentSymbol;
	result: EUAIActAnalysisResponse;
	codeHash: string;
}

// Store the latest EU AI Act analysis result for showing detailed explanation
let lastEUAIActResult: EUAIActAnalysisResponse | null = null;

// Map to store EU AI Act analysis results by document URI
export const documentEUAIActResults = new Map<string, FunctionEUAIActResult[]>();

/**
 * Sleep for specified number of milliseconds
 * @param ms Milliseconds to sleep
 */
function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Make API request with retry logic for rate limits
 * @param makeRequest Function to make the API request
 * @param maxRetries Maximum number of retries
 * @returns Promise with the API result
 */
async function makeRequestWithRetry<T>(
	makeRequest: () => Promise<T>, 
	maxRetries: number = 2
): Promise<T> {
	let lastError: Error | undefined;
	
	for (let attempt = 0; attempt <= maxRetries; attempt++) {
		try {
			return await makeRequest();
		} catch (error: any) {
			lastError = error;
			
			// Check if it's a rate limit error
			if (error.message.includes('Rate limit exceeded') && attempt < maxRetries) {
				// Extract retry delay from error message or use default
				const retryMatch = error.message.match(/Try again in (\d+) seconds/);
				const retryDelay = retryMatch ? parseInt(retryMatch[1]) * 1000 : 60000; // Default 60 seconds
				
				console.log(`Rate limit hit, retrying in ${retryDelay}ms (attempt ${attempt + 1}/${maxRetries + 1})`);
				
				// Show notification about retry
				vscode.window.showInformationMessage(
					`Rate limit hit. Retrying in ${retryDelay / 1000} seconds... (attempt ${attempt + 1}/${maxRetries + 1})`
				);
				
				await sleep(retryDelay);
				continue;
			}
			
			// If it's not a rate limit error or we've exhausted retries, throw the error
			throw error;
		}
	}
	
	throw new Error(lastError?.message || 'Unknown error occurred');
}

/**
 * Internal function to send the code to an API for EU AI Act analysis (without retry)
 * @param code The code to analyze
 * @param apiBaseUrl The base URL for the API
 * @param selectedModel The selected model for analysis
 * @param apiKey The API key for authentication
 * @returns EU AI Act analysis result
 */
async function analyzeCodeForEUAIActInternal(code: string, apiBaseUrl: string, selectedModel: string, apiKey: string, filePath?: string, startLine?: number, endLine?: number): Promise<EUAIActAnalysisResult> {
	// Get the full API URL for EU AI Act analyze endpoint
	const apiUrl = `${apiBaseUrl}/analyze-eu-ai-act`;

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
				'Authorization': `Bearer ${apiKey}`,
			}
		};

		const req = http.request(options, (res: any) => {
			let data = '';

			// Handle 429 Too Many Requests
			if (res.statusCode === 429) {
				const retryAfter = res.headers['retry-after'];
				
				// Show rate limit error with retry information
				const retryMessage = retryAfter 
					? `Rate limit exceeded. Try again in ${retryAfter} seconds.`
					: 'Rate limit exceeded. Please try again later.';
				
				vscode.window.showWarningMessage(retryMessage);
				
				return reject(new Error(`Rate limit exceeded. ${retryMessage}`));
			}

			// Handle other HTTP status errors
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

		// Send the code, model, and location information to analyze
		const requestBody = JSON.stringify({
			code,
			model: selectedModel,
			filePath: filePath,
			startLine: startLine,
			endLine: endLine
		});
		req.write(requestBody);
		req.end();
	});
}

/**
 * Send the code to an API for EU AI Act analysis (with retry logic)
 * @param code The code to analyze
 * @param apiBaseUrl The base URL for the API
 * @param selectedModel The selected model for analysis
 * @param apiKey The API key for authentication
 * @returns EU AI Act analysis result
 */
export async function analyzeCodeForEUAIAct(code: string, apiBaseUrl: string, selectedModel: string, apiKey: string, filePath?: string, startLine?: number, endLine?: number): Promise<EUAIActAnalysisResult> {
	return await makeRequestWithRetry(() => analyzeCodeForEUAIActInternal(code, apiBaseUrl, selectedModel, apiKey, filePath, startLine, endLine));
}

/**
 * Get the appropriate decoration type based on EU AI Act analysis result
 */
export function getEUAIActDecorationForResult(result: EUAIActAnalysisResponse, activeDecorations: vscode.TextEditorDecorationType[]): vscode.TextEditorDecorationType {
	let decorationType;
	if (result.status === EUAIActViolationStatus.Violation) {
		// Create a custom decoration for this specific EU AI Act violation
		decorationType = vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(255, 165, 0, 0.2)', // Orange for EU AI Act violations
			after: {
				contentText: ` 🇪🇺 ${result.article || 'EU AI Act Violation'}`,
				color: 'orange'
			}
		});
	} else {
		decorationType = vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(0, 100, 255, 0.2)', // Blue for compliance
			after: {
				contentText: ' 🇪🇺 Compliant',
				color: 'blue'
			}
		});
	}

	// Add to active decorations for tracking
	activeDecorations.push(decorationType);
	return decorationType;
}

/**
 * Shows detailed explanation of the last EU AI Act analysis result
 */
export function showEUAIActDetailedExplanation() {
	if (!lastEUAIActResult || !lastEUAIActResult.response) {
		vscode.window.showInformationMessage('No EU AI Act analysis details available.');
		return;
	}

	// Create a read-only webview panel to display the explanation
	const panel = vscode.window.createWebviewPanel(
		'euAIActDetails',
		'EU AI Act Compliance Analysis',
		vscode.ViewColumn.Beside,
		{
			enableScripts: true,
			localResourceRoots: [],
			retainContextWhenHidden: true
		}
	);

	// Set HTML content with the formatted explanation
	panel.webview.html = getEUAIActWebviewContent(lastEUAIActResult);
}

/**
 * Format the HTML content for the EU AI Act webview panel
 */
function getEUAIActWebviewContent(result: EUAIActAnalysisResponse): string {
	const violationStyle = 'color: #ff6600; background-color: rgba(255, 165, 0, 0.1); padding: 5px;';
	const compliantStyle = 'color: #0066ff; background-color: rgba(0, 100, 255, 0.1); padding: 5px;';
	const statusStyle = result.status === EUAIActViolationStatus.Violation ? violationStyle : compliantStyle;
	const statusEmoji = result.status === EUAIActViolationStatus.Violation ? '⚠️' : '✅';
	const statusText = result.status === EUAIActViolationStatus.Violation ? 'Violation Detected' : 'Compliant';

	return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>EU AI Act Compliance Analysis</title>
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
                .eu-flag {
                    font-size: 1.2em;
                    margin-right: 5px;
                }
                blockquote {
                    border-left: 4px solid #0066ff;
                    padding-left: 16px;
                    margin-left: 0;
                    color: #555;
                }
            </style>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/markdown-it/12.3.2/markdown-it.min.js"></script>
            <script>
                const vscode = acquireVsCodeApi();
                
                document.addEventListener('DOMContentLoaded', () => {
                    const md = window.markdownit({
                        html: false,
                        linkify: true,
                        typographer: true
                    });
                    
                    const content = ${JSON.stringify(result.response || '')};
                    const markdownElement = document.getElementById('markdown-content');
                    if (markdownElement) {
                        markdownElement.innerHTML = md.render(content);
                    }
                });
            </script>
        </head>
        <body>
            <h1><span class="eu-flag">🇪🇺</span>EU AI Act Compliance Analysis</h1>
            
            <h2>Compliance Status</h2>
            <div class="status">${statusEmoji} ${statusText}</div>
            
            ${result.article ? `<h2>Article Reference</h2><div>${result.article}</div>` : ''}
            ${result.violationType ? `<h2>Violation Type</h2><div>${result.violationType}</div>` : ''}
            
            <h2>Detailed Analysis</h2>
            <div class="explanation" id="markdown-content"></div>
        </body>
        </html>
    `;
}

/**
 * Shows EU AI Act details for a specific function
 * @param documentUri The URI of the document
 * @param line The line number of the function
 * @param result The EU AI Act analysis result
 */
export async function showEUAIActFunctionDetails(documentUri: string, line: number, result: EUAIActAnalysisResponse): Promise<void> {
	// Set the last EU AI Act result for the detailed explanation
	lastEUAIActResult = result;

	// Show the EU AI Act detailed explanation
	showEUAIActDetailedExplanation();
}

/**
 * Get document symbols using the document symbol provider
 * @param document The document to get symbols from
 * @returns Array of document symbols
 */
export async function getDocumentSymbols(document: vscode.TextDocument): Promise<vscode.DocumentSymbol[]> {
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