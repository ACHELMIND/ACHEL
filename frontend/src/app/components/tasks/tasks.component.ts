import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-tasks',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="tasks">
      <h2>Tasks</h2>
      
      <div class="controls">
        <select [(ngModel)]="selectedAgent">
          <option value="">Select Agent</option>
          <option *ngFor="let agent of agents" [value]="agent.id">
            {{ agent.hostname }} ({{ agent.internal_ip }})
          </option>
        </select>
        
        <select [(ngModel)]="selectedCommand">
          <option value="">Select Command</option>
          <option value="shell">Shell Command</option>
          <option value="powershell">PowerShell</option>
          <option value="screenshot">Screenshot</option>
          <option value="keylog_start">Start Keylogger</option>
          <option value="keylog_stop">Stop Keylogger</option>
          <option value="download">Download File</option>
          <option value="upload">Upload File</option>
          <option value="mimikatz">Mimikatz</option>
          <option value="hashdump">Hash Dump</option>
        </select>
        
        <input type="text" [(ngModel)]="commandArgs" placeholder="Arguments..." class="command-input">
        
        <button class="btn-primary" (click)="createTask()">Create Task</button>
      </div>

      <div class="tasks-table">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Agent</th>
              <th>Command</th>
              <th>Arguments</th>
              <th>Status</th>
              <th>Created</th>
              <th>Completed</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let task of tasks">
              <td>{{ task.id }}</td>
              <td>{{ task.agent_id }}</td>
              <td>{{ task.command }}</td>
              <td>{{ task.arguments }}</td>
              <td>
                <span class="status-badge" [class]="task.status">{{ task.status }}</span>
              </td>
              <td>{{ task.created_at | date:'short' }}</td>
              <td>{{ task.completed_at | date:'short' }}</td>
              <td>
                <button class="btn-small btn-danger" (click)="cancelTask(task)" 
                        *ngIf="task.status === 'pending'">Cancel</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="no-tasks" *ngIf="tasks.length === 0">
        <p>No tasks found</p>
      </div>
    </div>
  `,
  styles: [`
    .tasks {
      padding: 1rem;
    }
    .controls {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }
    select, input {
      padding: 0.5rem;
      border: 1px solid #ddd;
      border-radius: 4px;
    }
    .command-input {
      flex: 1;
      min-width: 200px;
    }
    .btn-primary, .btn-small {
      padding: 0.5rem 1rem;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    .btn-primary {
      background: #1a1a2e;
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
    .tasks-table {
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
    .status-badge {
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      text-transform: uppercase;
    }
    .status-badge.pending {
      background: #ffc107;
      color: #000;
    }
    .status-badge.running {
      background: #17a2b8;
      color: white;
    }
    .status-badge.completed {
      background: #28a745;
      color: white;
    }
    .status-badge.failed {
      background: #dc3545;
      color: white;
    }
    .no-tasks {
      text-align: center;
      padding: 2rem;
      color: #666;
    }
  `]
})
export class TasksComponent implements OnInit {
  agents: any[] = [];
  tasks: any[] = [];
  selectedAgent = '';
  selectedCommand = '';
  commandArgs = '';

  constructor(private apiService: ApiService) {}

  ngOnInit(): void {
    this.loadAgents();
    this.loadTasks();
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

  loadTasks(): void {
    this.apiService.getTasks().subscribe({
      next: (data) => {
        this.tasks = data;
      },
      error: (err) => {
        console.error('Failed to load tasks:', err);
      }
    });
  }

  createTask(): void {
    if (!this.selectedAgent || !this.selectedCommand) {
      alert('Please select an agent and command');
      return;
    }

    const task = {
      agent_id: this.selectedAgent,
      command: this.selectedCommand,
      arguments: this.commandArgs
    };

    this.apiService.createTask(task).subscribe({
      next: () => {
        this.loadTasks();
        this.commandArgs = '';
      },
      error: (err) => {
        console.error('Failed to create task:', err);
      }
    });
  }

  cancelTask(task: any): void {
    this.apiService.cancelTask(task.id).subscribe({
      next: () => {
        this.loadTasks();
      },
      error: (err) => {
        console.error('Failed to cancel task:', err);
      }
    });
  }
}
