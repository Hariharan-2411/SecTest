export class TestReporter {
  constructor() {
    this.testResults = {
      timestamp: new Date().toISOString(),
      url: '',
      formsFound: 0,
      inputsFound: 0,
      textareasFound: 0,
      selectsFound: 0,
      fileInputsFound: 0,
      actionsPerformed: [],
      screenshots: [],
      domSnapshots: []
    };
  }

  captureFormData(elements) {
    this.testResults.formsFound = new Set(elements.map(el => {
      let node = el.element;
      while (node && node.tagName !== 'FORM') {
        node = node.parentElement;
      }
      return node;
    }).filter(Boolean)).size;

    this.testResults.inputsFound = elements.filter(e => e.type === 'input').length;
    this.testResults.textareasFound = elements.filter(e => e.type === 'textarea').length;
    this.testResults.selectsFound = elements.filter(e => e.type === 'select').length;
    this.testResults.fileInputsFound = elements.filter(e => e.type === 'file').length;
  }

  addAction(action, element, result) {
    this.testResults.actionsPerformed.push({
      timestamp: new Date().toISOString(),
      action,
      element: {
        type: element.type,
        name: element.name,
        id: element.id
      },
      result
    });
  }

  async captureScreenshot() {
    return new Promise((resolve) => {
      chrome.tabs.captureVisibleTab(null, { format: 'png' }, (dataUrl) => {
        if (chrome.runtime.lastError) {
          console.error('Screenshot error:', chrome.runtime.lastError);
          resolve(null);
          return;
        }
        this.testResults.screenshots.push({
          timestamp: new Date().toISOString(),
          data: dataUrl
        });
        resolve(dataUrl);
      });
    });
  }

  captureDOMSnapshot() {
    const snapshot = {
      timestamp: new Date().toISOString(),
      html: document.documentElement.outerHTML,
      url: window.location.href,
      title: document.title
    };
    this.testResults.domSnapshots.push(snapshot);
    return snapshot;
  }

  generateReport() {
    const report = {
      ...this.testResults,
      summary: {
        totalElements: this.testResults.inputsFound + 
                      this.testResults.textareasFound + 
                      this.testResults.selectsFound + 
                      this.testResults.fileInputsFound,
        totalActions: this.testResults.actionsPerformed.length,
        successfulActions: this.testResults.actionsPerformed.filter(a => a.result === 'SUCCESS').length,
        screenshotsCaptured: this.testResults.screenshots.length,
        domSnapshotsCaptured: this.testResults.domSnapshots.length
      }
    };

    return report;
  }

  exportReport(format = 'json') {
    const report = this.generateReport();
    
    if (format === 'json') {
      return JSON.stringify(report, null, 2);
    }
    
    if (format === 'html') {
      return this.generateHTMLReport(report);
    }
    
    return report;
  }

  generateHTMLReport(report) {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>SecureInspect - Coverage Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #667eea; }
        h2 { color: #764ba2; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 36px; font-weight: bold; }
        .stat-label { font-size: 14px; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #667eea; color: white; }
        .success { color: #4caf50; font-weight: bold; }
        .failed { color: #f44336; font-weight: bold; }
        .screenshot { max-width: 300px; border: 2px solid #ddd; border-radius: 4px; margin: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SecureInspect - Coverage Report</h1>
        <p><strong>Generated:</strong> ${report.timestamp}</p>
        <p><strong>URL:</strong> ${report.url}</p>

        <h2>Summary</h2>
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">${report.summary.totalElements}</div>
                <div class="stat-label">Total Elements</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${report.formsFound}</div>
                <div class="stat-label">Forms Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${report.fileInputsFound}</div>
                <div class="stat-label">File Inputs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${report.summary.totalActions}</div>
                <div class="stat-label">Actions Taken</div>
            </div>
        </div>

        <h2>Element Breakdown</h2>
        <table>
            <tr>
                <th>Element Type</th>
                <th>Count</th>
            </tr>
            <tr><td>Input Fields</td><td>${report.inputsFound}</td></tr>
            <tr><td>Text Areas</td><td>${report.textareasFound}</td></tr>
            <tr><td>Select Dropdowns</td><td>${report.selectsFound}</td></tr>
            <tr><td>File Uploads</td><td>${report.fileInputsFound}</td></tr>
        </table>

        <h2>Actions Performed</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Element</th>
                <th>Result</th>
            </tr>
            ${report.actionsPerformed.map(action => `
            <tr>
                <td>${new Date(action.timestamp).toLocaleTimeString()}</td>
                <td>${action.action}</td>
                <td>${action.element.name} (${action.element.type})</td>
                <td class="${action.result.toLowerCase()}">${action.result}</td>
            </tr>
            `).join('')}
        </table>

        <h2>Screenshots (${report.screenshots.length})</h2>
        <div class="screenshots">
            ${report.screenshots.map((screenshot, idx) => `
                <img src="${screenshot.data}" class="screenshot" alt="Screenshot ${idx + 1}" />
            `).join('')}
        </div>
    </div>
</body>
</html>
    `;
  }
}

export default TestReporter;
