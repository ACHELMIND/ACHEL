# ANGEL Platform Frontend

Angular-based frontend for the ANGEL offensive security platform.

## Features

- **Dashboard**: Real-time statistics and activity monitoring
- **Agents**: Manage connected implant agents
- **Tasks**: Create and manage task assignments
- **Reports**: Generate and export assessment reports

## Prerequisites

- Node.js 18+
- npm or yarn

## Installation

```bash
cd frontend
npm install
```

## Development

```bash
npm start
```

Navigate to `http://localhost:4200/`.

## Build

```bash
npm run build
```

Build artifacts will be stored in `dist/angel-frontend/`.

## Testing

```bash
npm run test
```

## Project Structure

```
frontend/
├── src/
│   ├── app/
│   │   ├── components/
│   │   │   ├── dashboard/
│   │   │   ├── agents/
│   │   │   ├── tasks/
│   │   │   └── reports/
│   │   ├── services/
│   │   │   └── api.service.ts
│   │   ├── models/
│   │   ├── app.component.ts
│   │   ├── app.config.ts
│   │   └── app.routes.ts
│   ├── environments/
│   │   ├── environment.ts
│   │   └── environment.prod.ts
│   ├── styles.css
│   └── index.html
├── angular.json
├── package.json
└── tsconfig.json
```

## API Integration

The frontend communicates with the ANGEL teamserver API:

- `GET /api/v1/stats` - Dashboard statistics
- `GET /api/v1/agents` - List agents
- `DELETE /api/v1/agents/:id` - Kill agent
- `GET /api/v1/tasks` - List tasks
- `POST /api/v1/tasks` - Create task
- `GET /api/v1/reports` - List reports
- `POST /api/v1/reports` - Generate report

## Configuration

Environment files are located in `src/environments/`:

- `environment.ts` - Development configuration
- `environment.prod.ts` - Production configuration

## License

Private - Authorized use only
