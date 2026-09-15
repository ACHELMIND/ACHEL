import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-reports',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="reports">
      <h2>Reports</h2>
      
      <div class="controls">
        <button class="btn-primary" (click)="generateReport()">Generate Report</button>
        <button class="btn-secondary" (click)="exportReport('pdf')">Export PDF</button>
        <button class="btn-secondary" (click)="exportReport('html')">Export HTML</button>
      </div>

      <div class="reports-list">
        <div *ngFor="let report of reports" class="report-card">
          <div class="report-header">
            <h3>{{ report.title }}</h3>
            <span class="report-date">{{ report.created_at | date:'medium' }}</span>
          </div>
          <div class="report-summary">
            <p>{{ report.summary }}</p>
          </div>
          <div class="report-stats">
            <span class="stat">
              <strong>Critical:</strong> {{ report.critical_count }}
            </span>
            <span class="stat">
              <strong>High:</strong> {{ report.high_count }}
            </span>
            <span class="stat">
              <strong>Medium:</strong> {{ report.medium_count }}
            </span>
            <span class="stat">
              <strong>Low:</strong> {{ report.low_count }}
            </span>
          </div>
          <div class="report-actions">
            <button class="btn-small" (click)="viewReport(report)">View</button>
            <button class="btn-small" (click)="downloadReport(report)">Download</button>
          </div>
        </div>
      </div>

      <div class="no-reports" *ngIf="reports.length === 0">
        <p>No reports generated yet</p>
      </div>
    </div>
  `,
  styles: [`
    .reports {
      padding: 1rem;
    }
    .controls {
      margin-bottom: 1rem;
    }
    .btn-primary, .btn-secondary, .btn-small {
      padding: 0.5rem 1rem;
      margin-right: 0.5rem;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    .btn-primary {
      background: #1a1a2e;
      color: white;
    }
    .btn-secondary {
      background: #6c757d;
      color: white;
    }
    .btn-small {
      padding: 0.25rem 0.5rem;
      font-size: 0.8rem;
    }
    .reports-list {
      display: grid;
      gap: 1rem;
    }
    .report-card {
      background: white;
      padding: 1.5rem;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .report-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }
    .report-header h3 {
      margin: 0;
      color: #1a1a2e;
    }
    .report-date {
      color: #666;
      font-size: 0.9rem;
    }
    .report-summary {
      color: #333;
      margin-bottom: 1rem;
    }
    .report-stats {
      display: flex;
      gap: 1.5rem;
      margin-bottom: 1rem;
    }
    .stat {
      font-size: 0.9rem;
    }
    .report-actions {
      border-top: 1px solid #eee;
      padding-top: 1rem;
    }
    .no-reports {
      text-align: center;
      padding: 2rem;
      color: #666;
    }
  `]
})
export class ReportsComponent implements OnInit {
  reports: any[] = [];

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

  generateReport(): void {
    this.apiService.generateReport().subscribe({
      next: () => {
        this.loadReports();
      },
      error: (err) => {
        console.error('Failed to generate report:', err);
      }
    });
  }

  viewReport(report: any): void {
    console.log('Viewing report:', report);
  }

  downloadReport(report: any): void {
    this.apiService.downloadReport(report.id).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${report.id}.pdf`;
        a.click();
      },
      error: (err) => {
        console.error('Failed to download report:', err);
      }
    });
  }

  exportReport(format: string): void {
    console.log('Exporting report as:', format);
  }
}
