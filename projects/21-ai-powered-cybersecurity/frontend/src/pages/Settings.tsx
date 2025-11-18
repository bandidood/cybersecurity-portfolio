import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Switch,
  FormControlLabel,
  TextField,
  Button,
  Divider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Alert,
  Tabs,
  Tab,
} from '@mui/material';
import {
  Settings as SettingsIcon,
  Security,
  Notifications,
  Palette,
  DataUsage,
  Api,
} from '@mui/icons-material';
import { toast } from 'react-hot-toast';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`settings-tabpanel-${index}`}
      aria-labelledby={`settings-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

const Settings: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);

  // General Settings State
  const [enableAnalytics, setEnableAnalytics] = useState(true);
  const [enableNotifications, setEnableNotifications] = useState(true);
  const [darkMode, setDarkMode] = useState(true);
  const [language, setLanguage] = useState('en');

  // Security Settings State
  const [sessionTimeout, setSessionTimeout] = useState(60);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [autoLogout, setAutoLogout] = useState(true);

  // Threat Intelligence Settings State
  const [autoUpdate, setAutoUpdate] = useState(true);
  const [feedSources, setFeedSources] = useState(['misp', 'opencti', 'alienvault']);
  const [severityThreshold, setSeverityThreshold] = useState('medium');

  // ML Model Settings State
  const [autoRetrain, setAutoRetrain] = useState(false);
  const [confidenceThreshold, setConfidenceThreshold] = useState(0.8);
  const [modelRefreshInterval, setModelRefreshInterval] = useState(24);

  // API Settings State
  const [apiEndpoint, setApiEndpoint] = useState('http://localhost:8000');
  const [apiTimeout, setApiTimeout] = useState(30);
  const [apiRateLimit, setApiRateLimit] = useState(100);

  const handleSave = () => {
    // Save settings logic here
    const settings = {
      general: { enableAnalytics, enableNotifications, darkMode, language },
      security: { sessionTimeout, mfaEnabled, autoLogout },
      threatIntel: { autoUpdate, feedSources, severityThreshold },
      mlModels: { autoRetrain, confidenceThreshold, modelRefreshInterval },
      api: { apiEndpoint, apiTimeout, apiRateLimit },
    };

    console.log('Saving settings:', settings);
    toast.success('Settings saved successfully!');
  };

  const handleReset = () => {
    // Reset to defaults
    toast.success('Settings reset to defaults');
  };

  return (
    <Box>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 700 }}>
          <SettingsIcon sx={{ mr: 2, verticalAlign: 'middle', fontSize: '2rem' }} />
          Platform Settings
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Configure platform settings, security preferences, and AI model parameters
        </Typography>
      </Box>

      <Card>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={activeTab} onChange={(_, newValue) => setActiveTab(newValue)}>
            <Tab icon={<SettingsIcon />} label="General" />
            <Tab icon={<Security />} label="Security" />
            <Tab icon={<DataUsage />} label="Threat Intel" />
            <Tab icon={<Palette />} label="ML Models" />
            <Tab icon={<Api />} label="API" />
          </Tabs>
        </Box>

        <CardContent sx={{ p: 4 }}>
          {/* General Settings */}
          <TabPanel value={activeTab} index={0}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  General Preferences
                </Typography>
                <Divider sx={{ mb: 3 }} />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={enableAnalytics}
                      onChange={(e) => setEnableAnalytics(e.target.checked)}
                    />
                  }
                  label="Enable Analytics"
                />
                <Typography variant="caption" display="block" color="text.secondary">
                  Collect usage analytics to improve platform performance
                </Typography>
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={enableNotifications}
                      onChange={(e) => setEnableNotifications(e.target.checked)}
                    />
                  }
                  label="Enable Notifications"
                />
                <Typography variant="caption" display="block" color="text.secondary">
                  Receive real-time notifications for security events
                </Typography>
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={darkMode}
                      onChange={(e) => setDarkMode(e.target.checked)}
                    />
                  }
                  label="Dark Mode"
                />
                <Typography variant="caption" display="block" color="text.secondary">
                  Use dark theme for the interface
                </Typography>
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControl fullWidth>
                  <InputLabel>Language</InputLabel>
                  <Select
                    value={language}
                    label="Language"
                    onChange={(e) => setLanguage(e.target.value)}
                  >
                    <MenuItem value="en">English</MenuItem>
                    <MenuItem value="fr">Français</MenuItem>
                    <MenuItem value="de">Deutsch</MenuItem>
                    <MenuItem value="es">Español</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Security Settings */}
          <TabPanel value={activeTab} index={1}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Security Configuration
                </Typography>
                <Divider sx={{ mb: 3 }} />
                <Alert severity="warning" sx={{ mb: 3 }}>
                  Changes to security settings may require re-authentication
                </Alert>
              </Grid>

              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Session Timeout (minutes)"
                  value={sessionTimeout}
                  onChange={(e) => setSessionTimeout(parseInt(e.target.value))}
                  helperText="Automatically log out after this period of inactivity"
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={mfaEnabled}
                      onChange={(e) => setMfaEnabled(e.target.checked)}
                    />
                  }
                  label="Multi-Factor Authentication"
                />
                <Typography variant="caption" display="block" color="text.secondary">
                  Require MFA for sensitive operations
                </Typography>
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={autoLogout}
                      onChange={(e) => setAutoLogout(e.target.checked)}
                    />
                  }
                  label="Auto Logout on Idle"
                />
                <Typography variant="caption" display="block" color="text.secondary">
                  Automatically log out when session timeout is reached
                </Typography>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Threat Intelligence Settings */}
          <TabPanel value={activeTab} index={2}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Threat Intelligence Configuration
                </Typography>
                <Divider sx={{ mb: 3 }} />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={autoUpdate}
                      onChange={(e) => setAutoUpdate(e.target.checked)}
                    />
                  }
                  label="Auto-Update Threat Feeds"
                />
                <Typography variant="caption" display="block" color="text.secondary">
                  Automatically fetch latest threat intelligence data
                </Typography>
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControl fullWidth>
                  <InputLabel>Severity Threshold</InputLabel>
                  <Select
                    value={severityThreshold}
                    label="Severity Threshold"
                    onChange={(e) => setSeverityThreshold(e.target.value)}
                  >
                    <MenuItem value="critical">Critical Only</MenuItem>
                    <MenuItem value="high">High & Above</MenuItem>
                    <MenuItem value="medium">Medium & Above</MenuItem>
                    <MenuItem value="low">All Severities</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12}>
                <Typography variant="subtitle2" gutterBottom>
                  Active Threat Feed Sources
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
                  {feedSources.map((source) => (
                    <Chip key={source} label={source.toUpperCase()} color="primary" />
                  ))}
                </Box>
              </Grid>
            </Grid>
          </TabPanel>

          {/* ML Model Settings */}
          <TabPanel value={activeTab} index={3}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  ML Model Configuration
                </Typography>
                <Divider sx={{ mb: 3 }} />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={autoRetrain}
                      onChange={(e) => setAutoRetrain(e.target.checked)}
                    />
                  }
                  label="Auto-Retrain Models"
                />
                <Typography variant="caption" display="block" color="text.secondary">
                  Automatically retrain models with new data
                </Typography>
              </Grid>

              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Confidence Threshold"
                  value={confidenceThreshold}
                  onChange={(e) => setConfidenceThreshold(parseFloat(e.target.value))}
                  inputProps={{ min: 0, max: 1, step: 0.05 }}
                  helperText="Minimum confidence score for predictions (0-1)"
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Model Refresh Interval (hours)"
                  value={modelRefreshInterval}
                  onChange={(e) => setModelRefreshInterval(parseInt(e.target.value))}
                  helperText="How often to check for model updates"
                />
              </Grid>
            </Grid>
          </TabPanel>

          {/* API Settings */}
          <TabPanel value={activeTab} index={4}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  API Configuration
                </Typography>
                <Divider sx={{ mb: 3 }} />
              </Grid>

              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API Endpoint"
                  value={apiEndpoint}
                  onChange={(e) => setApiEndpoint(e.target.value)}
                  helperText="Backend API base URL"
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="API Timeout (seconds)"
                  value={apiTimeout}
                  onChange={(e) => setApiTimeout(parseInt(e.target.value))}
                  helperText="Request timeout for API calls"
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Rate Limit (requests/minute)"
                  value={apiRateLimit}
                  onChange={(e) => setApiRateLimit(parseInt(e.target.value))}
                  helperText="Maximum API requests per minute"
                />
              </Grid>
            </Grid>
          </TabPanel>

          {/* Action Buttons */}
          <Box sx={{ mt: 4, display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button variant="outlined" onClick={handleReset}>
              Reset to Defaults
            </Button>
            <Button variant="contained" onClick={handleSave}>
              Save Settings
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default Settings;