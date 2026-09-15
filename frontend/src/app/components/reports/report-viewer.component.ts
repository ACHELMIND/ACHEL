import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-report-viewer',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="report-viewer">
      <div class="viewer-header">
        <h3>Report Viewer</h3>
        <div class="viewer-controls">
          <select [(ngModel)]="selectedReport" (change)="loadReport()">
            <option value="">Select Report</option>
            <option *ngFor="let report of reports" [value]="report.id">
              {{ report.title }} - {{ report.created_at | date:'short' }}
            </option>
          </select>
          <button class="btn-export" (click)="exportReport('pdf')">Export PDF</button>
          <button class="btn-export" (click)="exportReport('html')">Export HTML</button>
        </div>
      </div>

      <div class="report-content" *ngIf="currentReport">
        <div class="report-meta">
          <h2>{{ currentReport.title }}</h2>
          <div class="meta-info">
            <span><strong>Created:</strong> {{ currentReport.created_at | date:'medium' }}</span>
            <span><strong>Classification:</strong> {{ currentReport.classification }}</span>
          </div>
        </div>

        <div class="report-section">
          <h4>Executive Summary</h4>
          <p>{{ currentReport.executive_summary }}</p>
        </div>

        <div class="report-section">
          <h4>Severity Distribution</h4>
          <div class="severity-grid">
            <div class="severity-card critical">
              <span class="count">{{ currentReport.critical_count }}</span>
              <span class="label">Critical</span>
            </div>
            <div class="severity-card high">
              <span class="count">{{ currentReport.high_count }}</span>
              <span class="label">High</span>
            </div>
            <div class="severity-card medium">
              <span class="count">{{ currentReport.medium_count }}</span>
              <span class="label">Medium</span>
            </div>
            <div class="severity-card low">
              <span class="count">{{ currentReport.low_count }}</span>
              <span class="label">Low</span>
            </div>
          </div>
        </div>

        <div class="report-section">
          <h4>Findings</h4>
          <div class="findings-list">
            <div *ngFor="let finding of currentReport.findings" class="finding-card" [class]="finding.severity">
              <div class="finding-header">
                <span class="finding-title">{{ finding.title }}</span>
                <span class="finding-severity" [class]="finding.severity">{{ finding.severity }}</span>
              </div>
              <p class="finding-description">{{ finding.description }}</p>
              <div class="finding-meta">
                <span><strong>CWE:</strong> {{ finding.cwe }}</span>
                <span><strong>MITRE:</strong> {{ finding.mitre }}</span>
                <span><strong>CVSS:</strong> {{ finding.cvss }}</span>
              </div>
              <div class="finding-remediation">
                <h5>Remediation:</h5>
                <p>{{ finding.remediation }}</p>
              </div>
            </div>
          </div>
        </div>

        <div class="report-section">
          <h4>Evidence Chain of Custody</h4>
          <div class="evidence-list">
            <div *ngFor="let evidence of currentReport.evidence" class="evidence-item">
              <div class="evidence-info">
                <span class="evidence-id">{{ evidence.id }}</span>
                <span class="evidence-hash">{{ evidence.hash }}</span>
              </div>
              <span class="evidence-timestamp">{{ evidence.timestamp | date:'medium' }}</span>
            </div>
          </div>
        </div>

        <div class="report-section">
          <h4>MITRE ATT&CK Mapping</h4>
          <div class="mitre-grid">
            <div *ngFor="let mapping of currentReport.mitre_mapping" class="mitre-item">
              <span class="tactic">{{ mapping.tactic }}</span>
              <span class="technique">{{ mapping.technique }}</span>
              <span class="count">{{ mapping.count }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="no-report" *ngIf="!currentReport">
        <p>Select a report to view</p>
      </div>
    </div>
  `,
  styles: [`
    .report-viewer {
      display: flex;
      flex-direction: column;
      height: 100%;
    }
    .viewer-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem;
      background: #f8f9fa;
      border-bottom: 1px solid #dee2e6;
    }
    .viewer-header h3 {
      margin: 0;
      color: #1a1a2e;
    }
    .viewer-controls {
      display: flex;
      gap: 0.5rem;
    }
    select, button {
      padding: 0.5rem 1rem;
      border: 1px solid #dee2e6;
      border-radius: 4px;
      font-size: 0.9rem;
    }
    .btn-export {
      background: #1a1a2e;
      color: white;
      border: none;
    }
    .btn-export:hover {
      background: #2d2d44;
    }
    .report-content {
      flex: 1;
      overflow-y: auto;
      padding: 1.5rem;
    }
    .report-meta {
      margin-bottom: 2rem;
    }
    .report-meta h2 {
      margin: 0 0 0.5rem 0;
      color: #1a1a2e;
    }
    .meta-info {
      display: flex;
      gap: 2rem;
      color: #666;
    }
    .report-section {
      margin-bottom: 2rem;
      background: white;
      padding: 1.5rem;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .report-section h4 {
      margin: 0 0 1rem 0;
      color: #1a1a2e;
      border-bottom: 2px solid #1a1a2e;
      padding-bottom: 0.5rem;
    }
    .severity-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
    }
    .severity-card {
      text-align: center;
      padding: 1rem;
      border-radius: 8px;
    }
    .severity-card .count {
      display: block;
      font-size: 2rem;
      font-weight: bold;
    }
    .severity-card .label {
      font-size: 0.9rem;
      text-transform: uppercase;
    }
    .severity-card.critical {
      background: #f8d7da;
      color: #721c24;
    }
    .severity-card.high {
      background: #fff3cd;
      color: #856404;
    }
    .severity-card.medium {
      background: #d1ecf1;
      color: #0c5460;
    }
    .severity-card.low {
      background: #d4edda;
      color: #155724;
    }
    .finding-card {
      border: 1px solid #dee2e6;
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1rem;
    }
    .finding-card.critical {
      border-left: 4px solid #dc3545;
    }
    .finding-card.high {
      border-left: 4px solid #ffc107;
    }
    .finding-card.medium {
      border-left: 4px solid #17a2b8;
    }
    .finding-card.low {
      border-left: 4px solid #28a745;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      margin-bottom: 0.5rem;
    }
    .finding-title {
      font-weight: bold;
      color: #1a1a2e;
    }
    .finding-severity {
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      text-transform: uppercase;
    }
    .finding-description {
      color: #666;
      margin: 0.5rem 0;
    }
    .finding-meta {
      display: flex;
      gap: 1rem;
      font-size: 0.85rem;
      color: #888;
    }
    .finding-remediation {
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid #eee;
    }
    .finding-remediation h5 {
      margin: 0 0 0.5rem 0;
      color: #1a1a2e;
    }
    .evidence-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.75rem;
      background: #f8f9fa;
      border-radius: 4px;
      margin-bottom: 0.5rem;
    }
    .evidence-id {
      font-weight: bold;
      color: #1a1a2e;
    }
    .evidence-hash {
      font-family: monospace;
      color: #666;
      font-size: 0.85rem;
    }
    .evidence-timestamp {
      color: #888;
      font-size: 0.85rem;
    }
    .mitre-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 0.5rem;
    }
    .mitre-item {
      display: flex;
      flex-direction: column;
      padding: 0.5rem;
      background: #f8f9fa;
      border-radius: 4px;
    }
    .mitre-item .tactic {
      font-weight: bold;
      color: #1a1a2e;
      font-size: 0.85rem;
    }
    .mitre-item .technique {
      color: #666;
      font-size: 0.8rem;
    }
    .mitre-item .count {
      color: #888;
      font-size: 0.75rem;
    }
    .no-report {
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100%;
      color: #666;
    }
  `]
})
export class ReportViewerComponent implements OnInit {
  reports: any[] = [];
  selectedReport = '';
  currentReport: any = null;

  constructor(private apiService: ApiService) {}

  ngOnInit(): void {
    this.loadReports();
  }

  loadReports(): void {
    this.apiService.getReports().subscribe({
      next: (data) => {
        this.reports = data;
      },
      error: (err) => {
        console.error('Failed to load reports:', err);
      }
    });
  }

  loadReport(): void {
    if (!this.selectedReport) {
      this.currentReport = null;
      return;
    }

    this.apiService.getReport(this.selectedReport).subscribe({
      next: (data) => {
        this.currentReport = data;
      },
      error: (err) => {
        console.error('Failed to load report:', err);
      }
    });
  }

  exportReport(format: string): void {
    if (!this.currentReport) {
      return;
    }

    this.apiService.downloadReport(this.currentReport.id).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${this.currentReport.id}.${format}`;
        a.click();
      },
      error: (err) => {
        console.error('Failed to export report:', err);
      }
    });
  }
}
