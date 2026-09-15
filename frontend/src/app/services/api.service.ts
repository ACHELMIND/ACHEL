import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private apiUrl = '/api/v1';

  constructor(private http: HttpClient) {}

  // Stats
  getStats(): Observable<any> {
    return this.http.get(`${this.apiUrl}/stats`).pipe(
      catchError(this.handleError)
    );
  }

  getRecentActivity(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/activity`).pipe(
      catchError(this.handleError)
    );
  }

  // Agents
  getAgents(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/agents`).pipe(
      catchError(this.handleError)
    );
  }

  getAgent(id: string): Observable<any> {
    return this.http.get(`${this.apiUrl}/agents/${id}`).pipe(
      catchError(this.handleError)
    );
  }

  killAgent(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/agents/${id}`).pipe(
      catchError(this.handleError)
    );
  }

  killAllAgents(): Observable<any> {
    return this.http.delete(`${this.apiUrl}/agents`).pipe(
      catchError(this.handleError)
    );
  }

  // Tasks
  getTasks(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/tasks`).pipe(
      catchError(this.handleError)
    );
  }

  createTask(task: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/tasks`, task).pipe(
      catchError(this.handleError)
    );
  }

  cancelTask(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/tasks/${id}`).pipe(
      catchError(this.handleError)
    );
  }

  // Results
  getResults(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/results`).pipe(
      catchError(this.handleError)
    );
  }

  // Reports
  getReports(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/reports`).pipe(
      catchError(this.handleError)
    );
  }

  generateReport(): Observable<any> {
    return this.http.post(`${this.apiUrl}/reports`, {}).pipe(
      catchError(this.handleError)
    );
  }

  downloadReport(id: string): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/reports/${id}/download`, {
      responseType: 'blob'
    }).pipe(
      catchError(this.handleError)
    );
  }

  // Health
  healthCheck(): Observable<any> {
    return this.http.get(`${this.apiUrl}/health`).pipe(
      catchError(this.handleError)
    );
  }

  private handleError(error: HttpErrorResponse) {
    let errorMessage = 'An error occurred';
    if (error.error instanceof ErrorEvent) {
      errorMessage = error.error.message;
    } else {
      errorMessage = `Error Code: ${error.status}\nMessage: ${error.message}`;
    }
    console.error(errorMessage);
    return throwError(() => new Error(errorMessage));
  }
}
