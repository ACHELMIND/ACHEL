import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet],
  template: `
    <div class="app-container">
      <header class="app-header">
        <h1>ANGEL Platform</h1>
        <nav>
          <a routerLink="/dashboard">Dashboard</a>
          <a routerLink="/agents">Agents</a>
          <a routerLink="/tasks">Tasks</a>
          <a routerLink="/reports">Reports</a>
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
    .app-header nav a {
      color: white;
      text-decoration: none;
      margin-left: 1rem;
    }
    .app-header nav a:hover {
      text-decoration: underline;
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
  `]
})
export class AppComponent {
  title = 'angel-frontend';
}
