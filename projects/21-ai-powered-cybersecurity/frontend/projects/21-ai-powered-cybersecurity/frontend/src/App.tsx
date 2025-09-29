import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { Toaster } from 'react-hot-toast';

// Layout Components
import MainLayout from './components/layout/MainLayout';

// Page Components
import Dashboard from './pages/Dashboard';
import LogAnalysis from './pages/LogAnalysis';
import ThreatIntelligence from './pages/ThreatIntelligence';
import IncidentAnalysis from './pages/IncidentAnalysis';
import Settings from './pages/Settings';

// Create cybersecurity-themed dark theme
const cybersecurityTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00d4ff', // Cyber blue
      light: '#4de5ff',
      dark: '#0099cc',
      contrastText: '#000',
    },
    secondary: {
      main: '#ff6b35', // Warning orange
      light: '#ff9966',
      dark: '#cc4400',
      contrastText: '#fff',
    },
    error: {
      main: '#ff1744', // Critical red
      light: '#ff5983',
      dark: '#c4001d',
    },
    warning: {
      main: '#ffa726', // Alert amber
      light: '#ffb74d',
      dark: '#f57c00',
    },
    success: {
      main: '#4caf50', // Safe green
      light: '#7cbf7c',
      dark: '#2e7d32',
    },
    info: {
      main: '#29b6f6', // Info blue
      light: '#73e8ff',
      dark: '#0086c3',
    },
    background: {
      default: '#0a0e13', // Deep dark background
      paper: '#162027', // Card background
    },
    text: {
      primary: '#e0e6ed', // Light text
      secondary: '#9ca3af', // Muted text
    },
    divider: 'rgba(255, 255, 255, 0.12)',
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: '2.5rem',
      fontWeight: 700,
      letterSpacing: '-0.025em',
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 600,
      letterSpacing: '-0.025em',
    },
    h3: {
      fontSize: '1.75rem',
      fontWeight: 600,
    },
    h4: {
      fontSize: '1.5rem',
      fontWeight: 600,
    },
    h5: {
      fontSize: '1.25rem',
      fontWeight: 600,
    },
    h6: {
      fontSize: '1.125rem',
      fontWeight: 600,
    },
    body1: {
      fontSize: '1rem',
      lineHeight: 1.6,
    },
    body2: {
      fontSize: '0.875rem',
      lineHeight: 1.5,
    },
  },
  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: '#162027',
          borderRadius: '12px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          backdropFilter: 'blur(10px)',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: '#162027',
          backgroundImage: 'none',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: '8px',
          textTransform: 'none',
          fontWeight: 500,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: '6px',
        },
      },
    },
  },
});

const App: React.FC = () => {
  return (
    <ThemeProvider theme={cybersecurityTheme}>
      <CssBaseline />
      <Router>
        <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
          <MainLayout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/log-analysis" element={<LogAnalysis />} />
              <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
              <Route path="/incident-analysis" element={<IncidentAnalysis />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </MainLayout>
        </Box>
      </Router>
      
      {/* Global toast notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#162027',
            color: '#e0e6ed',
            border: '1px solid rgba(255, 255, 255, 0.1)',
          },
          success: {
            iconTheme: {
              primary: '#4caf50',
              secondary: '#162027',
            },
          },
          error: {
            iconTheme: {
              primary: '#ff1744',
              secondary: '#162027',
            },
          },
        }}
      />
    </ThemeProvider>
  );
};

export default App;