import { Routes } from '@angular/router';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { AgentsComponent } from './components/agents/agents.component';
import { TasksComponent } from './components/tasks/tasks.component';
import { ReportsComponent } from './components/reports/reports.component';
import { AgentConsoleComponent } from './components/console/console.component';
import { ReportViewerComponent } from './components/reports/report-viewer.component';

export const routes: Routes = [
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
  { path: 'dashboard', component: DashboardComponent },
  { path: 'agents', component: AgentsComponent },
  { path: 'tasks', component: TasksComponent },
  { path: 'reports', component: ReportsComponent },
  { path: 'console', component: AgentConsoleComponent },
  { path: 'report-viewer', component: ReportViewerComponent },
  { path: '**', redirectTo: '/dashboard' }
];
