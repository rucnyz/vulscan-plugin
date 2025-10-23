# VirtueGuard-Code README

This is the README for our extension "VirtueGuard-Code", a powerful vulnerability scanning tool for your code.

## 1. Configuration

### 1.1 API Base URL

You can set the API base URL by setting the `vulscan.apiBaseUrl` in the `settings.json` file. The default URL is "https://guard-code-backend.virtueai.io".

### 1.2 Auto-Analysis Settings

You can enable or disable automatic analysis on file save by setting `vulscan.autoAnalyzeOnSave` to `true` or `false` in your settings.

### 1.3 API Key

You can set the API key by setting the `vulscan.apiKey`.

To get your API key, please contact us by [booking a demo](https://meetings.hubspot.com/shekhar-bapat).

### 1.4 Selected Model

You can select the model to use for vulnerability analysis by setting the `vulscan.selectedModel`. The default model is "virtueguard-code".

The available models are:
- virtueguard-code
- claude-4-sonnet
- gpt-4.1

## 2. How to use

We support two modes for vulnerability scanning:

### 2.1 Autoscan Mode

This mode automatically scans your code for vulnerabilities whenever you save a file. It's perfect for continuous security monitoring during development.

Features:
- Automatic analysis on file save
- Real-time vulnerability detection
- Visual indicators for vulnerable code sections
- Detailed vulnerability reports with CWE types

To enable this mode:
1. Open VS Code settings
2. Search for "vulscan.autoAnalyzeOnSave"
3. Set it to `true`

![automode](https://github.com/user-attachments/assets/a19afe73-0abf-407c-8173-c2192c8cafbe)

### 2.2 Manual Scan Mode

This mode allows you to analyze specific code sections for vulnerabilities. It's ideal for targeted security reviews.

Features:
- Select any code section for analysis
- Deep dependency analysis
- Implementation context awareness
- Detailed vulnerability reports

To use this mode:
1. Select the code you want to analyze
2. Right-click and choose "VulScan: Analyze Selected Code" or use the command palette
3. View the analysis results and improvement suggestions

![manual](https://github.com/user-attachments/assets/bd089934-9f55-47b4-b3a8-7754dd009071)






