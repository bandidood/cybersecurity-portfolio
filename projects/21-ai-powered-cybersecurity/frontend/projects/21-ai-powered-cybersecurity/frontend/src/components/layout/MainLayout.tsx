import React, { useState } from 'react';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  List,
  Typography,
  Divider,
  IconButton,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Badge,
  Avatar,
  Menu,
  MenuItem,
  Tooltip,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Assessment as AssessmentIcon,
  Security as SecurityIcon,
  Sync as SyncIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  AccountCircle as AccountIcon,
  ChevronLeft as ChevronLeftIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material';
import { useLocation, useNavigate } from 'react-router-dom';

const drawerWidth = 280;

interface MainLayoutProps {
  children: React.ReactNode;
}

interface NavigationItem {
  text: string;
  icon: React.ReactElement;
  path: string;
  badge?: number;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const [open, setOpen] = useState(true);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const location = useLocation();
  const navigate = useNavigate();

  const navigationItems: NavigationItem[] = [
    {
      text: 'Dashboard',
      icon: <DashboardIcon />,
      path: '/dashboard',
    },
    {
      text: 'Log Analysis',
      icon: <AssessmentIcon />,
      path: '/log-analysis',
      badge: 3, // Mock badge for new alerts
    },
    {
      text: 'Threat Intelligence',
      icon: <SecurityIcon />,
      path: '/threat-intelligence',
      badge: 1,
    },
    {
      text: 'Incident Analysis',
      icon: <SyncIcon />,
      path: '/incident-analysis',
    },
    {
      text: 'Settings',
      icon: <SettingsIcon />,
      path: '/settings',
    },
  ];

  const handleDrawerToggle = () => {
    setOpen(!open);
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleNavigation = (path: string) => {
    navigate(path);
  };

  const isActive = (path: string) => {
    return location.pathname === path || (path === '/dashboard' && location.pathname === '/');
  };

  return (
    <Box sx={{ display: 'flex' }}>
      {/* App Bar */}
      <AppBar
        position="fixed"
        sx={{
          zIndex: (theme) => theme.zIndex.drawer + 1,
          backgroundColor: 'rgba(10, 14, 19, 0.95)',
          backdropFilter: 'blur(20px)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            onClick={handleDrawerToggle}
            edge="start"
            sx={{ mr: 2 }}
          >
            {open ? <ChevronLeftIcon /> : <MenuIcon />}
          </IconButton>

          {/* Logo and Title */}
          <Box sx={{ display: 'flex', alignItems: 'center', flexGrow: 1 }}>
            <ShieldIcon sx={{ mr: 1, color: 'primary.main', fontSize: 28 }} />
            <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 700 }}>
              AI CyberGuard
            </Typography>
            <Typography
              variant="caption"
              sx={{
                ml: 1,
                px: 1,
                py: 0.25,
                bgcolor: 'primary.main',
                color: 'primary.contrastText',
                borderRadius: 1,
                fontSize: '0.65rem',
                fontWeight: 600,
              }}
            >
              BETA
            </Typography>
          </Box>

          {/* Header Actions */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {/* Notifications */}
            <Tooltip title="Notifications">
              <IconButton color="inherit">
                <Badge badgeContent={5} color="error">
                  <NotificationsIcon />
                </Badge>
              </IconButton>
            </Tooltip>

            {/* User Menu */}
            <Tooltip title="Account">
              <IconButton onClick={handleMenuOpen} color="inherit">
                <Avatar
                  sx={{
                    width: 32,
                    height: 32,
                    bgcolor: 'primary.main',
                    fontSize: '0.875rem',
                    fontWeight: 600,
                  }}
                >
                  SA
                </Avatar>
              </IconButton>
            </Tooltip>
          </Box>
        </Toolbar>
      </AppBar>

      {/* User Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
        PaperProps={{
          sx: {
            mt: 1.5,
            minWidth: 200,
            backgroundColor: '#162027',
            border: '1px solid rgba(255, 255, 255, 0.1)',
          },
        }}
      >
        <MenuItem onClick={handleMenuClose}>
          <AccountIcon sx={{ mr: 2 }} />
          Profile
        </MenuItem>
        <MenuItem onClick={handleMenuClose}>
          <SettingsIcon sx={{ mr: 2 }} />
          Settings
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleMenuClose}>
          Logout
        </MenuItem>
      </Menu>

      {/* Side Navigation Drawer */}
      <Drawer
        variant="persistent"
        anchor="left"
        open={open}
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
            backgroundColor: '#0f1419',
            borderRight: '1px solid rgba(255, 255, 255, 0.1)',
            overflowX: 'hidden',
          },
        }}
      >
        {/* Drawer Header */}
        <Toolbar />
        
        <Box sx={{ overflow: 'auto', pt: 2 }}>
          {/* Quick Stats */}
          <Box sx={{ px: 2, mb: 3 }}>
            <Typography variant="overline" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
              System Status
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
              <Box
                sx={{
                  flex: 1,
                  p: 1.5,
                  bgcolor: 'rgba(76, 175, 80, 0.1)',
                  border: '1px solid rgba(76, 175, 80, 0.3)',
                  borderRadius: 1,
                  textAlign: 'center',
                }}
              >
                <Typography variant="h6" color="success.main" sx={{ fontSize: '1rem' }}>
                  98%
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Healthy
                </Typography>
              </Box>
              <Box
                sx={{
                  flex: 1,
                  p: 1.5,
                  bgcolor: 'rgba(255, 167, 38, 0.1)',
                  border: '1px solid rgba(255, 167, 38, 0.3)',
                  borderRadius: 1,
                  textAlign: 'center',
                }}
              >
                <Typography variant="h6" color="warning.main" sx={{ fontSize: '1rem' }}>
                  24
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Alerts
                </Typography>
              </Box>
            </Box>
          </Box>

          <Divider />

          {/* Navigation Items */}
          <List sx={{ px: 1, mt: 2 }}>
            {navigationItems.map((item) => (
              <ListItem key={item.text} disablePadding sx={{ mb: 0.5 }}>
                <ListItemButton
                  onClick={() => handleNavigation(item.path)}
                  selected={isActive(item.path)}
                  sx={{
                    borderRadius: 1,
                    mx: 1,
                    '&.Mui-selected': {
                      bgcolor: 'rgba(0, 212, 255, 0.15)',
                      borderLeft: '3px solid',
                      borderLeftColor: 'primary.main',
                      '&:hover': {
                        bgcolor: 'rgba(0, 212, 255, 0.2)',
                      },
                    },
                    '&:hover': {
                      bgcolor: 'rgba(255, 255, 255, 0.05)',
                    },
                  }}
                >
                  <ListItemIcon
                    sx={{
                      color: isActive(item.path) ? 'primary.main' : 'text.secondary',
                      minWidth: 40,
                    }}
                  >
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.text}
                    primaryTypographyProps={{
                      fontSize: '0.875rem',
                      fontWeight: isActive(item.path) ? 600 : 400,
                      color: isActive(item.path) ? 'primary.main' : 'text.primary',
                    }}
                  />
                  {item.badge && (
                    <Badge
                      badgeContent={item.badge}
                      color="error"
                      sx={{
                        '& .MuiBadge-badge': {
                          fontSize: '0.75rem',
                          height: 18,
                          minWidth: 18,
                        },
                      }}
                    />
                  )}
                </ListItemButton>
              </ListItem>
            ))}
          </List>

          {/* Security Notice */}
          <Box sx={{ p: 2, mt: 4 }}>
            <Box
              sx={{
                p: 2,
                bgcolor: 'rgba(0, 212, 255, 0.1)',
                border: '1px solid rgba(0, 212, 255, 0.3)',
                borderRadius: 2,
              }}
            >
              <Typography variant="caption" color="primary.main" sx={{ fontWeight: 600 }}>
                🔒 Secure Connection Active
              </Typography>
              <Typography variant="caption" display="block" color="text.secondary" sx={{ mt: 0.5 }}>
                All data is encrypted and processed securely
              </Typography>
            </Box>
          </Box>
        </Box>
      </Drawer>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          transition: 'margin-left 0.3s ease',
          marginLeft: open ? 0 : `-${drawerWidth}px`,
          minHeight: '100vh',
          backgroundColor: 'background.default',
        }}
      >
        <Toolbar />
        {children}
      </Box>
    </Box>
  );
};

export default MainLayout;