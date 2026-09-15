import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-agents',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="agents">
      <h2>Agents</h2>
      
      <div class="controls">
        <button class="btn-primary" (click)="refreshAgents()">Refresh</button>
        <button class="btn-secondary" (click)="killAllAgents()">Kill All</button>
      </div>

      <div class="agents-table">
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Internal IP</th>
              <th>User</th>
              <th>Process</th>
              <th>OS</th>
              <th>Sleep</th>
              <th>Last Check-in</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let agent of agents" [class.online]="agent.online">
              <td>{{ agent.hostname }}</td>
              <td>{{ agent.internal_ip }}</td>
              <td>{{ agent.user }}</td>
              <td>{{ agent.process_id }}</td>
              <td>{{ agent.os }}</td>
              <td>{{ agent.sleep_interval }}s</td>
              <td>{{ agent.last_checkin | date:'short' }}</td>
              <td>
                <button class="btn-small" (click)="interactAgent(agent)">Interact</button>
                <button class="btn-small btn-danger" (click)="killAgent(agent)">Kill</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="no-agents" *ngIf="agents.length === 0">
        <p>No agents connected</p>
      </div>
    </div>
  `,
  styles: [`
    .agents {
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
    .btn-danger {
      background: #dc3545;
      color: white;
    }
    .agents-table {
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      overflow: hidden;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid #eee;
    }
    th {
      background: #f8f9fa;
      font-weight: bold;
    }
    tr:hover {
      background: #f8f9fa;
    }
    tr.online {
      background: #d4edda;
    }
    .no-agents {
      text-align: center;
      padding: 2rem;
      color: #666;
    }
  `]
})
export class AgentsComponent implements OnInit {
  agents: any[] = [];

  constructor(private apiService: ApiService) {}

  ngOnInit(): void {
    this.loadAgents();
  }

  loadAgents(): void {
    this.apiService.getAgents().subscribe({
      next: (data) => {
        this.agents = data;
      },
      error: (err) => {
        console.error('Failed to load agents:', err);
      }
    });
  }

  refreshAgents(): void {
    this.loadAgents();
  }

  interactAgent(agent: any): void {
    console.log('Interacting with agent:', agent);
  }

  killAgent(agent: any): void {
    if (confirm(`Kill agent ${agent.hostname}?`)) {
      this.apiService.killAgent(agent.id).subscribe({
        next: () => {
          this.loadAgents();
        },
        error: (err) => {
          console.error('Failed to kill agent:', err);
        }
      });
    }
  }

  killAllAgents(): void {
    if (confirm('Kill all agents?')) {
      this.apiService.killAllAgents().subscribe({
        next: () => {
          this.loadAgents();
        },
        error: (err) => {
          console.error('Failed to kill agents:', err);
        }
      });
    }
  }
}
