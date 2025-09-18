import * as vscode from 'vscode';

// Define interfaces for API responses
export interface AnalysisResponse {
	status: VulnerabilityStatus;
	cweType?: string;
	model?: string;
	response?: string;
}

export interface ExtractResponse {
	dependencies: string[];
	done?: boolean;
}

export interface AnalysisResult {
	result: AnalysisResponse;
	status: 'success' | 'error';
}

export interface ExtractResult {
	result: ExtractResponse;
	status: 'success' | 'error';
}

export interface TokenUsageResponse {
	tokens_used: number;
	token_limit: number;
	usage_percentage: number;
	is_near_limit: boolean;
}

// Define enum for vulnerability status
export enum VulnerabilityStatus {
	Benign = 'no',
	Vulnerable = 'yes'
}

/**
 * Make API request with basic error handling
 * @param makeRequest Function to make the API request
 * @returns Promise with the API result
 */
export async function makeRequestWithRetry<T>(
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
 * @param apiBaseUrl The API base URL
 * @param selectedModel The model to use
 * @param apiKey The API key
 * @returns Analysis result
 */
async function analyzeCodeForVulnerabilitiesInternal(
	code: string,
	languageId: string,
	apiBaseUrl: string,
	selectedModel: string,
	apiKey: string
): Promise<AnalysisResult> {
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
				'Authorization': `Bearer ${apiKey}`,
				'X-API-Key': apiKey
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
 * @param apiBaseUrl The API base URL
 * @param selectedModel The model to use
 * @param apiKey The API key
 * @returns Analysis result
 */
export async function analyzeCodeForVulnerabilities(
	code: string,
	languageId: string,
	apiBaseUrl: string,
	selectedModel: string,
	apiKey: string
): Promise<AnalysisResult> {
	return await makeRequestWithRetry(() =>
		analyzeCodeForVulnerabilitiesInternal(code, languageId, apiBaseUrl, selectedModel, apiKey)
	);
}

/**
 * Internal function to extract dependencies from code
 * @param code The code to analyze
 * @param round The round number (starting from 1)
 * @param apiBaseUrl The API base URL
 * @param selectedModel The model to use
 * @param apiKey The API key
 * @returns Object containing dependencies array and done flag
 */
async function extractDependenciesInternal(
	code: string,
	round: number,
	apiBaseUrl: string,
	selectedModel: string,
	apiKey: string
): Promise<ExtractResponse> {
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
				'Authorization': `Bearer ${apiKey}`,
				'X-API-Key': apiKey
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
 * @param apiBaseUrl The API base URL
 * @param selectedModel The model to use
 * @param apiKey The API key
 * @returns Object containing dependencies array and done flag
 */
export async function extractDependencies(
	code: string,
	round: number,
	apiBaseUrl: string,
	selectedModel: string,
	apiKey: string
): Promise<ExtractResponse> {
	return await makeRequestWithRetry(() =>
		extractDependenciesInternal(code, round, apiBaseUrl, selectedModel, apiKey)
	);
}

/**
 * Internal function to check token usage
 * @param apiBaseUrl The API base URL
 * @param apiKey The API key
 * @returns Token usage information
 */
async function checkTokenUsageInternal(apiBaseUrl: string, apiKey: string): Promise<TokenUsageResponse> {
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
				'X-API-Key': apiKey
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
 * Check token usage by making an API call
 * @param apiBaseUrl The API base URL
 * @param apiKey The API key
 * @returns Token usage information
 */
export async function checkTokenUsage(apiBaseUrl: string, apiKey: string): Promise<TokenUsageResponse> {
	return await makeRequestWithRetry(() => checkTokenUsageInternal(apiBaseUrl, apiKey));
}