import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="dashboard">
      <h2>Dashboard</h2>
      
      <div class="stats-grid">
        <div class="stat-card">
          <h3>Active Agents</h3>
          <p class="stat-value">{{ stats.activeAgents }}</p>
        </div>
        <div class="stat-card">
          <h3>Pending Tasks</h3>
          <p class="stat-value">{{ stats.pendingTasks }}</p>
        </div>
        <div class="stat-card">
          <h3>Completed Tasks</h3>
          <p class="stat-value">{{ stats.completedTasks }}</p>
        </div>
        <div class="stat-card">
          <h3>Credentials Found</h3>
          <p class="stat-value">{{ stats.credentialsFound }}</p>
        </div>
      </div>

      <div class="recent-activity">
        <h3>Recent Activity</h3>
        <div class="activity-list">
          <div *ngFor="let activity of recentActivity" class="activity-item">
            <span class="activity-type">{{ activity.type }}</span>
            <span class="activity-message">{{ activity.message }}</span>
            <span class="activity-time">{{ activity.timestamp | date:'short' }}</span>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .dashboard {
      padding: 1rem;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: white;
      padding: 1.5rem;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      text-align: center;
    }
    .stat-card h3 {
      margin: 0 0 0.5rem 0;
      color: #666;
      font-size: 0.9rem;
    }
    .stat-value {
      font-size: 2rem;
      font-weight: bold;
      color: #1a1a2e;
      margin: 0;
    }
    .recent-activity {
      background: white;
      padding: 1.5rem;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .activity-list {
      max-height: 300px;
      overflow-y: auto;
    }
    .activity-item {
      display: flex;
      padding: 0.75rem 0;
      border-bottom: 1px solid #eee;
    }
    .activity-type {
      font-weight: bold;
      color: #1a1a2e;
      min-width: 100px;
    }
    .activity-message {
      flex: 1;
      margin: 0 1rem;
    }
    .activity-time {
      color: #999;
    }
  `]
})
export class DashboardComponent implements OnInit {
  stats = {
    activeAgents: 0,
    pendingTasks: 0,
    completedTasks: 0,
    credentialsFound: 0
  };

  recentActivity: any[] = [];

  constructor(private apiService: ApiService) {}

  ngOnInit(): void {
    this.loadStats();
    this.loadRecentActivity();
  }

  loadStats(): void {
    this.apiService.getStats().subscribe({
      next: (data) => {
        this.stats = data;
      },
      error: (err) => {
        console.error('Failed to load stats:', err);
      }
    });
  }

  loadRecentActivity(): void {
    this.apiService.getRecentActivity().subscribe({
      next: (data) => {
        this.recentActivity = data;
      },
      error: (err) => {
        console.error('Failed to load activity:', err);
      }
    });
  }
}
