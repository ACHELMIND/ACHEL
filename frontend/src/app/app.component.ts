import { Component } from '@angular/core';
import { RouterOutlet, RouterLink } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink],
  template: `
    <div class="app-container">
      <header class="app-header">
        <h1>ANGEL Platform</h1>
        <nav>
          <a routerLink="/dashboard">Dashboard</a>
          <a routerLink="/agents">Agents</a>
          <a routerLink="/tasks">Tasks</a>
          <a routerLink="/console">Console</a>
          <a routerLink="/reports">Reports</a>
          <a routerLink="/report-viewer">Report Viewer</a>
        </nav>
      </header>
      <main class="app-content">
        <router-outlet></router-outlet>
      </main>
      <footer class="app-footer">
        <p>ANGEL Platform v1.0.0</p>
      </footer>
    </div>
  `,
  styles: [`
    .app-container {
      display: flex;
      flex-direction: column;
      min-height: 100vh;
    }
    .app-header {
      background: #1a1a2e;
      color: white;
      padding: 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .app-header h1 {
      margin: 0;
      font-size: 1.5rem;
    }
    .app-header nav {
      display: flex;
      gap: 1rem;
    }
    .app-header nav a {
      color: white;
      text-decoration: none;
      padding: 0.5rem 1rem;
      border-radius: 4px;
      transition: background 0.2s;
    }
    .app-header nav a:hover {
      background: rgba(255,255,255,0.1);
    }
    .app-content {
      flex: 1;
      padding: 2rem;
      background: #f5f5f5;
    }
    .app-footer {
      background: #1a1a2e;
      color: white;
      text-align: center;
      padding: 1rem;
    }
    .app-footer p {
      margin: 0;
    }
  `]
})
export class AppComponent {
  title = 'angel-frontend';
}
