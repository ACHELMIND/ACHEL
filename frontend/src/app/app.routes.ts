import { Routes } from '@angular/router';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { AgentsComponent } from './components/agents/agents.component';
import { TasksComponent } from './components/tasks/tasks.component';
import { ReportsComponent } from './components/reports/reports.component';

export const routes: Routes = [
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
  { path: 'dashboard', component: DashboardComponent },
  { path: 'agents', component: AgentsComponent },
  { path: 'tasks', component: TasksComponent },
  { path: 'reports', component: ReportsComponent },
  { path: '**', redirectTo: '/dashboard' }
];
