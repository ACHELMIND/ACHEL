import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, Subject, WebSocketSubject } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class WebSocketService {
  private apiUrl = '/api/v1';
  private wsUrl = 'ws://localhost:8080/ws';
  private connections: Map<string, WebSocketSubject<any>> = new Map();
  private messageSubjects: Map<string, Subject<any>> = new Map();

  constructor(private http: HttpClient) {}

  connect(agentId: string): Observable<any> {
    if (this.connections.has(agentId)) {
      return this.messageSubjects.get(agentId)!.asObservable();
    }

    const ws = new WebSocketSubject<any>(`${this.wsUrl}?agent=${agentId}`);
    const messageSubject = new Subject<any>();

    ws.subscribe({
      next: (message) => {
        messageSubject.next(message);
      },
      error: (error) => {
        messageSubject.error(error);
        this.connections.delete(agentId);
        this.messageSubjects.delete(agentId);
      },
      complete: () => {
        messageSubject.complete();
        this.connections.delete(agentId);
        this.messageSubjects.delete(agentId);
      }
    });

    this.connections.set(agentId, ws);
    this.messageSubjects.set(agentId, messageSubject);

    return messageSubject.asObservable();
  }

  disconnect(agentId: string): void {
    const ws = this.connections.get(agentId);
    if (ws) {
      ws.complete();
      this.connections.delete(agentId);
      this.messageSubjects.delete(agentId);
    }
  }

  sendCommand(agentId: string, command: string): Observable<any> {
    const ws = this.connections.get(agentId);
    if (ws) {
      ws.next({
        type: 'command',
        agent_id: agentId,
        command: command,
        timestamp: new Date().toISOString()
      });
    }

    return this.http.post(`${this.apiUrl}/tasks`, {
      agent_id: agentId,
      command: command
    }).pipe(
      catchError((error) => {
        throw error;
      })
    );
  }

  getAgents(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/agents`).pipe(
      catchError((error) => {
        throw error;
      })
    );
  }

  isConnected(agentId: string): boolean {
    return this.connections.has(agentId);
  }

  getActiveConnections(): string[] {
    return Array.from(this.connections.keys());
  }
}
