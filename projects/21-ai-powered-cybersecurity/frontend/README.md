# AI-Powered Cybersecurity Platform - Frontend

Modern React + TypeScript frontend for the AI-Powered Cybersecurity Platform.

## Tech Stack

- **Framework**: React 18
- **Language**: TypeScript 5
- **UI Library**: Material-UI (MUI) 5
- **Charts**: Recharts
- **State Management**: Zustand
- **Routing**: React Router v6
- **HTTP Client**: Axios
- **Forms**: React Hook Form
- **Styling**: Emotion (CSS-in-JS)

## Features

- Modern cybersecurity-themed dark UI
- Real-time threat visualization
- AI-powered log analysis interface
- Threat intelligence dashboard
- Incident analysis and management
- Comprehensive settings panel
- Responsive design for all screen sizes

## Project Structure

```
frontend/
├── public/                 # Static assets
├── src/
│   ├── components/        # Reusable components
│   │   ├── charts/       # Chart components (ThreatSeverityChart, TimeSeriesChart)
│   │   ├── widgets/      # Widget components (StatCard, AlertWidget)
│   │   └── layout/       # Layout components (MainLayout)
│   ├── pages/            # Page components
│   │   ├── Dashboard.tsx
│   │   ├── LogAnalysis.tsx
│   │   ├── ThreatIntelligence.tsx
│   │   ├── IncidentAnalysis.tsx
│   │   └── Settings.tsx
│   ├── services/         # API services
│   │   └── api.ts        # Centralized API client
│   ├── hooks/            # Custom React hooks
│   │   └── useApi.ts     # API interaction hooks
│   ├── utils/            # Utility functions
│   │   └── formatters.ts # Data formatting utilities
│   ├── types/            # TypeScript type definitions
│   ├── App.tsx           # Main app component
│   └── index.tsx         # App entry point
├── package.json
├── tsconfig.json
└── .env.example          # Environment variables template
```

## Getting Started

### Prerequisites

- Node.js 18+ and npm/yarn
- Backend API running on http://localhost:8000

### Installation

```bash
# Install dependencies
npm install

# Copy environment variables
cp .env.example .env

# Start development server
npm start
```

The application will open at http://localhost:3000

### Available Scripts

```bash
npm start       # Start development server
npm build       # Build for production
npm test        # Run tests
npm run lint    # Run ESLint
npm run format  # Format code with Prettier
```

## Environment Variables

Create a `.env` file based on `.env.example`:

```bash
REACT_APP_API_URL=http://localhost:8000
REACT_APP_API_TIMEOUT=30000
REACT_APP_ENABLE_ANALYTICS=true
```

## API Integration

The frontend communicates with the FastAPI backend through the centralized API service (`src/services/api.ts`).

### Using the API

```typescript
import { api } from '@/services/api';

// Analyze logs
const result = await api.logs.analyze(logData);

// Get threat intelligence
const threats = await api.threatIntel.iocs({ severity: 'high' });

// List incidents
const incidents = await api.incidents.list({ status: 'active' });
```

### Using Custom Hooks

```typescript
import { useFetch, useMutation } from '@/hooks/useApi';

// Fetch data with auto-refresh
const { data, loading, error } = useFetch(
  () => api.incidents.list(),
  [] // dependencies
);

// Perform mutations
const { mutate, loading } = useMutation(
  (data) => api.incidents.create(data)
);
```

## Component Usage

### Charts

```typescript
import { ThreatSeverityChart, TimeSeriesChart } from '@/components';

<ThreatSeverityChart
  data={threatData}
  title="Threat Distribution"
/>

<TimeSeriesChart
  data={timeSeriesData}
  dataKeys={['attacks', 'blocked']}
  title="Attack Trends"
/>
```

### Widgets

```typescript
import { StatCard, AlertWidget } from '@/components';

<StatCard
  title="Total Threats"
  value="1,234"
  change={12.5}
  icon={<WarningIcon />}
  color="#ff6b35"
/>

<AlertWidget
  alerts={recentAlerts}
  maxItems={5}
/>
```

## Theming

The application uses a custom cybersecurity-themed dark mode:

- **Primary Color**: Cyber Blue (#00d4ff)
- **Secondary Color**: Warning Orange (#ff6b35)
- **Background**: Deep Dark (#0a0e13)
- **Paper**: Card Background (#162027)

## Building for Production

```bash
# Create optimized production build
npm run build

# Build output will be in the 'build' directory
# Serve with any static file server
npx serve -s build
```

## Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Generate coverage report
npm test -- --coverage
```

## Code Quality

```bash
# Lint TypeScript files
npm run lint

# Fix linting issues
npm run lint:fix

# Format code
npm run format
```

## Performance Optimization

- Code splitting with React.lazy()
- Memoization with React.memo()
- Virtual scrolling for large lists
- Optimistic updates for better UX
- Image lazy loading
- Service worker for offline support

## Security Features

- Content Security Policy (CSP)
- XSS protection
- CSRF token handling
- Secure cookie management
- Input sanitization
- Rate limiting on API calls

## Accessibility

- WCAG 2.1 Level AA compliance
- Keyboard navigation support
- Screen reader friendly
- High contrast mode
- Focus indicators
- ARIA labels

## Browser Support

- Chrome/Edge (last 2 versions)
- Firefox (last 2 versions)
- Safari (last 2 versions)

## Contributing

1. Create a feature branch
2. Make your changes
3. Run tests and linting
4. Submit a pull request

## License

MIT License - See LICENSE file for details
