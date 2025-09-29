# AI CyberGuard Frontend 🔒⚡

Modern React TypeScript frontend for the AI-Powered Cybersecurity Platform, featuring advanced threat analysis and real-time monitoring capabilities.

## 🚀 Features

### 🎯 Core Modules
- **Dashboard**: Real-time security metrics and threat overview
- **Log Analysis**: Upload and analyze security logs with AI-powered IOC extraction
- **Threat Intelligence**: Process CTI reports with MITRE ATT&CK mapping
- **Incident Analysis**: Cross-correlation between logs and threat intel
- **Settings**: Platform configuration and preferences

### 🎨 UI/UX Highlights
- **Cybersecurity-themed dark design** with neon accents
- **Responsive layout** optimized for SOC environments
- **Interactive data visualizations** using Recharts
- **Animated transitions** with Framer Motion
- **Material-UI components** with custom theming
- **Drag & drop file uploads** for log analysis
- **Real-time progress indicators** and notifications

### 📊 Visualizations
- Threat activity timelines
- IOC type distributions  
- Severity level pie charts
- MITRE ATT&CK technique mapping
- Correlation confidence scoring
- Network topology graphs (planned)

## 🏗️ Architecture

### Technology Stack
- **React 18** with TypeScript
- **Material-UI (MUI)** for component library
- **Recharts** for data visualization
- **Framer Motion** for animations
- **React Router** for navigation
- **Zustand** for state management
- **React Query** for API data fetching
- **React Dropzone** for file uploads

### Project Structure
```
frontend/
├── public/                 # Static assets
├── src/
│   ├── components/        # Reusable UI components
│   │   ├── layout/       # Layout components (Header, Sidebar, etc.)
│   │   ├── dashboard/    # Dashboard-specific components  
│   │   ├── log-analysis/ # Log analysis components
│   │   ├── threat-intel/ # Threat intelligence components
│   │   ├── common/       # Shared components (Cards, Tables, etc.)
│   │   └── charts/       # Chart and visualization components
│   ├── pages/            # Page components
│   ├── hooks/            # Custom React hooks
│   ├── services/         # API service functions
│   ├── types/            # TypeScript type definitions
│   ├── utils/            # Utility functions
│   ├── stores/           # Zustand state stores
│   ├── App.tsx          # Main app component
│   └── index.tsx        # Application entry point
├── package.json
└── README.md
```

## 🚀 Quick Start

### Prerequisites
- **Node.js 16+** and npm/yarn
- **Python backend** running on localhost:8000 (for full functionality)

### Installation

1. **Navigate to frontend directory**:
```bash
cd projects/21-ai-powered-cybersecurity/frontend
```

2. **Install dependencies**:
```bash
npm install
# or
yarn install
```

3. **Start development server**:
```bash
npm start
# or
yarn start
```

4. **Open browser** to http://localhost:3000

### Build for Production
```bash
npm run build
# or
yarn build
```

## 🎯 Key Components

### Dashboard Page
- **Real-time metrics**: Threats detected, IOCs extracted, processing speed
- **Threat timeline**: Interactive area chart showing activity over time
- **Severity distribution**: Pie chart of threat levels
- **Recent alerts**: Live feed of security events
- **System health**: Resource usage and model performance

### Log Analysis Page
- **File upload zone**: Drag & drop interface for log files
- **Direct text input**: Quick analysis of pasted log entries  
- **Results table**: Expandable rows with detailed analysis
- **IOC extraction**: Automatic identification of security indicators
- **ML predictions**: AI-powered classification and prioritization
- **Filtering & search**: Advanced result filtering capabilities

### Threat Intelligence Page  
- **Report analysis**: Process CTI reports for IOCs and TTPs
- **Threat actor profiles**: Database of known APT groups
- **MITRE ATT&CK mapping**: Automatic technique identification
- **IOC intelligence**: Reputation scoring and enrichment
- **Campaign tracking**: Link related attacks and indicators

### Incident Analysis Page
- **Correlation engine**: Cross-reference logs with threat intel
- **Shared IOC detection**: Find common indicators across data sources
- **Threat actor attribution**: Link activities to known groups
- **Automated recommendations**: AI-generated security actions
- **Analysis timeline**: Step-by-step incident reconstruction

## 🎨 Design System

### Color Palette
- **Primary**: #00d4ff (Cyber Blue)
- **Secondary**: #ff6b35 (Warning Orange)  
- **Error**: #ff1744 (Critical Red)
- **Warning**: #ffa726 (Alert Amber)
- **Success**: #4caf50 (Safe Green)
- **Background**: #0a0e13 (Deep Dark)
- **Surface**: #162027 (Card Background)

### Typography
- **Font Family**: Inter (Google Fonts)
- **Hierarchy**: h1-h6 with proper weight distribution
- **Body Text**: Optimized for readability in dark theme
- **Code/Monospace**: For log entries and technical data

### Components
- **Cards**: Glassmorphism effect with blur and transparency
- **Buttons**: Rounded corners with hover animations
- **Tables**: Expandable rows for detailed information
- **Charts**: Custom color schemes matching the theme
- **Notifications**: Toast messages with contextual styling

## 📡 API Integration

### Backend Endpoints (Expected)
```typescript
// Log Analysis
POST /api/logs/analyze          // Analyze log entries
POST /api/logs/upload           // Upload log files
GET  /api/logs/results          // Get analysis results

// Threat Intelligence  
POST /api/threat-intel/analyze  // Analyze CTI reports
GET  /api/threat-intel/actors   // Get threat actor data
GET  /api/threat-intel/mitre    // Get MITRE ATT&CK data

// Incident Analysis
POST /api/incidents/correlate   // Run correlation analysis
GET  /api/incidents/history     // Get incident history
```

### Data Flow
1. **Frontend** sends analysis requests to FastAPI backend
2. **Backend** processes data using NLP models
3. **Results** returned as structured JSON
4. **Frontend** renders results with interactive visualizations

## 🔧 Configuration

### Environment Variables
```env
REACT_APP_API_BASE_URL=http://localhost:8000
REACT_APP_ENVIRONMENT=development
REACT_APP_VERSION=1.0.0
```

### Proxy Configuration
The `package.json` includes a proxy setting to forward API calls to the Python backend:
```json
"proxy": "http://localhost:8000"
```

## 🎯 Features Implementation Status

### ✅ Completed
- [x] Project structure and TypeScript setup
- [x] Material-UI theme and component library
- [x] Responsive layout with sidebar navigation
- [x] Dashboard with mock data visualizations
- [x] Log analysis interface with file upload
- [x] Threat intelligence pages with MITRE integration
- [x] Incident correlation dashboard
- [x] Animated transitions and interactions

### 🚧 In Progress  
- [ ] Real API integration with Python backend
- [ ] Advanced filtering and search functionality
- [ ] User authentication and session management
- [ ] Settings and configuration panels

### 📋 Planned
- [ ] Real-time WebSocket connections
- [ ] Advanced data visualizations (network graphs)
- [ ] Export functionality (PDF, CSV reports)
- [ ] Mobile responsiveness optimization
- [ ] Accessibility (a11y) improvements
- [ ] Internationalization (i18n) support

## 🧪 Testing

### Run Tests
```bash
npm test
# or
yarn test
```

### Linting
```bash
npm run lint
npm run lint:fix
```

### Code Formatting
```bash
npm run format
```

## 📱 Browser Support

- **Chrome/Edge**: Latest 2 versions
- **Firefox**: Latest 2 versions  
- **Safari**: Latest 2 versions
- **Mobile**: iOS 12+, Android 8+

## 🚀 Deployment

### Development
```bash
npm start
```

### Production Build
```bash
npm run build
```

### Docker (Planned)
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

## 🤝 Contributing

### Code Style
- **TypeScript** strict mode enabled
- **ESLint** configuration for React/TypeScript
- **Prettier** for code formatting
- **Conventional Commits** for commit messages

### Development Workflow
1. Create feature branch from `main`
2. Implement changes with TypeScript types
3. Add/update tests as needed
4. Run linting and formatting
5. Submit pull request with detailed description

## 📊 Performance

### Bundle Size Optimization
- **Code splitting** by route and feature
- **Tree shaking** for unused imports
- **Lazy loading** for heavy components
- **Image optimization** for assets

### Runtime Performance  
- **React.memo** for component memoization
- **useMemo/useCallback** for expensive computations
- **Virtual scrolling** for large data tables (planned)
- **Request deduplication** with React Query

## 📞 Support

For questions about the frontend implementation:
- Review component documentation in source files
- Check TypeScript interfaces in `/src/types/`
- Refer to Material-UI documentation for styling
- Test API integration with mock data first

## 📄 License

This frontend is part of the AI-Powered Cybersecurity Portfolio project. See the main repository for license information.

---

**Built with ❤️ for cybersecurity professionals**