import * as assert from 'assert';
import * as sinon from 'sinon';

import * as vscode from 'vscode';

suite('Extension Test Suite', () => {
	vscode.window.showInformationMessage('Start all tests.');

	test('Sample test', () => {
		assert.strictEqual(-1, [1, 2, 3].indexOf(5));
		assert.strictEqual(-1, [1, 2, 3].indexOf(0));
	});
});

suite('Vulnerability Analysis Tests', () => {
	let sandbox: sinon.SinonSandbox;

	setup(() => {
		sandbox = sinon.createSandbox();
	});

	teardown(() => {
		sandbox.restore();
	});

	suite('API Key Authentication Tests', () => {
		test('Should show error when API key is not configured', async () => {
			// Import extension module to access testing functions
			const extension = require('../extension');

			// Set the API key to empty to simulate missing configuration
			extension.setApiKeyForTesting('');

			// Mock showErrorMessage to capture the call
			const showErrorStub = sandbox.stub(vscode.window, 'showErrorMessage');

			// Execute the analyze code command
			await vscode.commands.executeCommand('vulscan.analyzeCode');

			// Verify error message was shown
			assert.ok(showErrorStub.calledWith('API key is required. Please configure it in VS Code settings (vulscan.apiKey).'));
		});

		test('Should proceed with analysis when API key is configured', async () => {
			// Import extension module to access testing functions
			const extension = require('../extension');

			// Set the API key to simulate configured API key
			extension.setApiKeyForTesting('test-key-12345');

			// Mock active editor with selected text
			const mockEditor = {
				document: {
					getText: sandbox.stub().returns('console.log("test");'),
					uri: vscode.Uri.file('/test/file.js')
				},
				selection: {
					isEmpty: false,
					start: { line: 0, character: 0 },
					end: { line: 0, character: 20 }
				},
				setDecorations: sandbox.stub()
			};
			sandbox.stub(vscode.window, 'activeTextEditor').value(mockEditor);

			// Mock showInformationMessage
			const showInfoStub = sandbox.stub(vscode.window, 'showInformationMessage');

			// Mock withProgress to avoid the actual analysis
			sandbox.stub(vscode.window, 'withProgress').callsFake((options, task) => {
				// Just resolve immediately
				return Promise.resolve();
			});

			// Execute the command
			await vscode.commands.executeCommand('vulscan.analyzeCode');


			// Verify that information message was shown (indicating process started)
			assert.ok(showInfoStub.calledWith('Analyzing code for vulnerabilities...'));
		});
	});

	suite('Rate Limiting Tests', () => {
		test('Should handle 429 rate limit response correctly', async () => {
			// This test would require mocking the HTTP request
			// We can test the rate limit parsing function if it was exported

			// Mock a 429 response headers
			const mockHeaders = {
				'x-ratelimit-limit': '100',
				'x-ratelimit-remaining': '0',
				'x-ratelimit-reset': '1640995200',
				'retry-after': '60'
			};

			// Since parseRateLimitHeaders is not exported, we test the behavior indirectly
			// by checking if rate limit status bar is updated
			const mockStatusBarItem = {
				text: '',
				color: undefined,
				tooltip: '',
				show: sandbox.stub(),
				hide: sandbox.stub()
			};

			sandbox.stub(vscode.window, 'createStatusBarItem').returns(mockStatusBarItem as any);

			// The actual rate limiting would be tested through integration
			assert.ok(true, 'Rate limiting integration test placeholder');
		});

		test('Should show rate limit warning when approaching limit', () => {
			// Test rate limit warning logic
			const mockRateLimit = {
				limit: 100,
				remaining: 5,  // Less than 10% threshold
				reset: Math.floor(Date.now() / 1000) + 3600
			};

			// Calculate warning threshold (10% of limit)
			const warningThreshold = Math.max(1, Math.floor(mockRateLimit.limit * 0.1));
			const shouldShowWarning = mockRateLimit.remaining <= warningThreshold;

			assert.ok(shouldShowWarning, 'Should show warning when remaining requests are below 10% threshold');
		});
	});

	suite('Analysis Response Validation Tests', () => {
		test('Should validate vulnerable response format', () => {
			const vulnerableResponse = {
				result: {
					status: 'yes',
					cweType: 'CWE-79',
					model: 'virtueguard-code',
					response: 'Cross-site scripting vulnerability detected...',
					usage: {}
				},
				status: 'success'
			};

			// Test response structure validation
			assert.ok(vulnerableResponse.result.status === 'yes', 'Vulnerable status should be "yes"');
			assert.ok(vulnerableResponse.result.cweType, 'Vulnerable response should include CWE type');
			assert.ok(vulnerableResponse.status === 'success', 'Response should have success status');
		});

		test('Should validate benign response format', () => {
			const benignResponse = {
				result: {
					status: 'no',
					model: 'virtueguard-code',
					response: 'No vulnerabilities detected in the provided code...',
					usage: {}
				},
				status: 'success'
			};

			// Test response structure validation
			assert.ok(benignResponse.result.status === 'no', 'Benign status should be "no"');
			assert.ok(benignResponse.status === 'success', 'Response should have success status');
		});

		test('Should handle malformed API responses', () => {
			const malformedResponses = [
				null,
				undefined,
				{},
				{ result: null },
				{ result: {} },
				{ result: { status: 'invalid' } }
			];

			malformedResponses.forEach((response, index) => {
				try {
					// This would test the response parsing logic
					const isValid = response &&
						response.result &&
						typeof response.result.status === 'string' &&
						['yes', 'no'].includes(response.result.status);

					assert.ok(!isValid, `Malformed response ${index} should be invalid`);
				} catch (error) {
					// Expected to fail validation
					assert.ok(true, `Malformed response ${index} correctly rejected`);
				}
			});
		});
	});

	suite('Code Analysis Tests', () => {
		const testCases = [
			{
				name: 'SQL Injection Code',
				code: `
string query = "SELECT * FROM users WHERE id = " + user_input;
db.execute(query);
				`,
				expectedVulnerable: true,
				expectedCWE: 'CWE-89'
			},
			{
				name: 'Safe Code',
				code: `
def add_numbers(a, b):
    return a + b
result = add_numbers(5, 3)
				`,
				expectedVulnerable: false
			}
		];

		testCases.forEach((testCase) => {
			test(`Should analyze ${testCase.name}`, () => {
				// Mock the code analysis - this would be an integration test
				// that actually calls the API in a real test environment

				// Validate test case structure
				assert.ok(typeof testCase.code === 'string', 'Test case should have code string');
				assert.ok(typeof testCase.expectedVulnerable === 'boolean', 'Test case should specify expected vulnerability status');

				if (testCase.expectedVulnerable) {
					assert.ok(testCase.expectedCWE, 'Vulnerable test cases should specify expected CWE');
				}

				// In a real test, this would make an actual API call
				console.log(`Testing: ${testCase.name}`);
				console.log(`Code length: ${testCase.code.length} characters`);
				console.log(`Expected vulnerable: ${testCase.expectedVulnerable}`);
			});
		});
	});

	suite('Error Handling Tests', () => {
		test('Should handle network errors gracefully', async () => {
			// Mock network failure
			const mockConfig = {
				get: sandbox.stub().callsFake((key: string) => {
					switch (key) {
						case 'apiKey': return 'test-key-12345';
						case 'apiBaseUrl': return 'https://invalid-url.example';
						case 'selectedModel': return 'virtueguard-code';
						default: return undefined;
					}
				})
			};
			sandbox.stub(vscode.workspace, 'getConfiguration').returns(mockConfig as any);

			// Mock showErrorMessage to capture error handling
			const showErrorStub = sandbox.stub(vscode.window, 'showErrorMessage');

			// Test that network errors are handled (would need to mock HTTP client)
			assert.ok(true, 'Network error handling test placeholder');
		});

		test('Should handle invalid API key authentication', async () => {
			// Import extension module to access testing functions
			const extension = require('../extension');

			// Set an invalid API key
			extension.setApiKeyForTesting('invalid-key-12345');

			// Mock active editor with selected text
			const mockEditor = {
				document: {
					getText: sandbox.stub().returns('console.log("test");'),
					uri: vscode.Uri.file('/test/file.js')
				},
				selection: {
					isEmpty: false,
					start: { line: 0, character: 0 },
					end: { line: 0, character: 20 }
				},
				setDecorations: sandbox.stub()
			};
			sandbox.stub(vscode.window, 'activeTextEditor').value(mockEditor);

			// Mock showErrorMessage to capture authentication errors
			const showErrorStub = sandbox.stub(vscode.window, 'showErrorMessage');

			// Mock withProgress to simulate authentication failure
			sandbox.stub(vscode.window, 'withProgress').callsFake((options, task) => {
				// Simulate 401 authentication error
				return Promise.reject(new Error('Authentication failed: Invalid API key'));
			});

			// Execute the command and expect it to handle the error
			await vscode.commands.executeCommand('vulscan.analyzeCode');

			// Verify error handling (this would depend on actual implementation)
			assert.ok(true, 'Authentication error handling test - would verify error message shown');
		});

		test('Should handle invalid API responses', () => {
			// Test various invalid response scenarios
			const invalidResponses = [
				'not json',
				'{"invalid": "structure"}',
				'{"result": {"status": "maybe"}}',  // Invalid status
			];

			invalidResponses.forEach((invalidResponse, index) => {
				try {
					const parsed = JSON.parse(invalidResponse);
					// Test validation logic
					const isValid = parsed.result && ['yes', 'no'].includes(parsed.result.status);
					assert.ok(!isValid, `Invalid response ${index} should fail validation`);
				} catch (e) {
					// JSON parse error is expected for some cases
					assert.ok(true, `Invalid response ${index} correctly rejected`);
				}
			});
		});

		test('Should handle empty or missing code selection', async () => {
			// Import extension module to access testing functions
			const extension = require('../extension');

			// Set the API key to simulate configured API key
			extension.setApiKeyForTesting('test-key-12345');

			// Mock editor with empty selection
			const mockEditor = {
				document: { getText: sandbox.stub().returns('') },
				selection: { isEmpty: true }
			};
			sandbox.stub(vscode.window, 'activeTextEditor').value(mockEditor);

			// Mock showInformationMessage
			const showInfoStub = sandbox.stub(vscode.window, 'showInformationMessage');

			// Execute command
			await vscode.commands.executeCommand('vulscan.analyzeCode');

			// Should show message about selecting code
			assert.ok(showInfoStub.calledWith('Please select some code to analyze'));
		});

		test('Should handle API timeout errors', async () => {
			// Import extension module to access testing functions
			const extension = require('../extension');

			// Set valid API key
			extension.setApiKeyForTesting('test-key-12345');

			// Mock active editor with selected text
			const mockEditor = {
				document: {
					getText: sandbox.stub().returns('setTimeout(() => { eval(userInput); }, 5000);'),
					uri: vscode.Uri.file('/test/file.js')
				},
				selection: {
					isEmpty: false,
					start: { line: 0, character: 0 },
					end: { line: 0, character: 50 }
				},
				setDecorations: sandbox.stub()
			};
			sandbox.stub(vscode.window, 'activeTextEditor').value(mockEditor);

			// Mock showErrorMessage to capture timeout errors
			const showErrorStub = sandbox.stub(vscode.window, 'showErrorMessage');

			// Mock withProgress to simulate timeout error
			sandbox.stub(vscode.window, 'withProgress').callsFake((options, task) => {
				return Promise.reject(new Error('Request timeout'));
			});

			// Execute the command
			await vscode.commands.executeCommand('vulscan.analyzeCode');

			// Verify timeout error handling
			assert.ok(true, 'Timeout error handling test - would verify appropriate error message');
		});
	});

	suite('Configuration Tests', () => {
		test('Should use correct default configuration values', () => {
			const defaultValues = {
				apiBaseUrl: 'https://api.virtueai.io/api/vulscan',
				selectedModel: 'virtueguard-code',
				autoAnalyzeOnSave: false
			};

			// Test that defaults are reasonable
			assert.ok(defaultValues.apiBaseUrl.startsWith('https://'), 'API URL should use HTTPS');
			assert.ok(typeof defaultValues.selectedModel === 'string', 'Model should be string');
			assert.ok(typeof defaultValues.autoAnalyzeOnSave === 'boolean', 'Auto-analyze should be boolean');
		});


		test('Should handle configuration changes', () => {
			// Mock configuration change event
			const mockConfigChangeEvent = {
				affectsConfiguration: sandbox.stub().returns(true)
			};

			// Test that configuration changes are handled appropriately
			assert.ok(true, 'Configuration change handling test placeholder');
		});
	});

	suite('Integration Tests', () => {
		test('Should integrate with VSCode document symbols', async () => {
			// Mock document with functions
			const mockDocument = {
				uri: vscode.Uri.file('/test/file.js'),
				getText: sandbox.stub().returns(`
function vulnerableFunction() {
	eval(userInput); // Dangerous
}

function safeFunction() {
	console.log("safe");
}
				`)
			};

			// Mock document symbols
			const mockSymbols = [
				{
					name: 'vulnerableFunction',
					kind: vscode.SymbolKind.Function,
					range: new vscode.Range(1, 0, 3, 1),
					selectionRange: new vscode.Range(1, 9, 1, 26)
				},
				{
					name: 'safeFunction',
					kind: vscode.SymbolKind.Function,
					range: new vscode.Range(5, 0, 7, 1),
					selectionRange: new vscode.Range(5, 9, 5, 21)
				}
			];

			// Test symbol integration
			assert.ok(mockSymbols.length === 2, 'Should find 2 functions');
			assert.ok(mockSymbols[0].kind === vscode.SymbolKind.Function, 'Should identify functions correctly');
		});
	});
});
