import { useState } from 'react';
import { Save, Bell, Shield, User, CreditCard } from 'lucide-react';

export function Settings() {
  const [settings, setSettings] = useState({
    // Profile
    displayName: 'Security Researcher',
    email: 'researcher@example.com',
    bio: 'Ethical hacker specializing in web application security',

    // Notifications
    emailNotifications: true,
    submissionUpdates: true,
    programAnnouncements: true,
    weeklyDigest: false,

    // Security
    twoFactorEnabled: true,
    apiAccessEnabled: false,
  });

  const handleSave = () => {
    // Handle settings save
    alert('Settings saved successfully!');
  };

  return (
    <div>
      <h1 className="text-3xl font-bold text-gray-900 mb-8">Settings</h1>

      <div className="space-y-6">
        {/* Profile Settings */}
        <SettingsSection
          icon={User}
          title="Profile Settings"
          description="Manage your personal information and profile"
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Display Name
              </label>
              <input
                type="text"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                value={settings.displayName}
                onChange={(e) => setSettings({ ...settings, displayName: e.target.value })}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Email Address
              </label>
              <input
                type="email"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                value={settings.email}
                onChange={(e) => setSettings({ ...settings, email: e.target.value })}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Bio
              </label>
              <textarea
                rows={3}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                value={settings.bio}
                onChange={(e) => setSettings({ ...settings, bio: e.target.value })}
              />
            </div>
          </div>
        </SettingsSection>

        {/* Notification Settings */}
        <SettingsSection
          icon={Bell}
          title="Notifications"
          description="Configure how you receive updates"
        >
          <div className="space-y-4">
            <SettingToggle
              label="Email Notifications"
              description="Receive email notifications for important updates"
              checked={settings.emailNotifications}
              onChange={(checked) => setSettings({ ...settings, emailNotifications: checked })}
            />
            <SettingToggle
              label="Submission Updates"
              description="Get notified when your submissions are reviewed"
              checked={settings.submissionUpdates}
              onChange={(checked) => setSettings({ ...settings, submissionUpdates: checked })}
            />
            <SettingToggle
              label="Program Announcements"
              description="Receive updates about new and modified programs"
              checked={settings.programAnnouncements}
              onChange={(checked) => setSettings({ ...settings, programAnnouncements: checked })}
            />
            <SettingToggle
              label="Weekly Digest"
              description="Get a weekly summary of your activity"
              checked={settings.weeklyDigest}
              onChange={(checked) => setSettings({ ...settings, weeklyDigest: checked })}
            />
          </div>
        </SettingsSection>

        {/* Security Settings */}
        <SettingsSection
          icon={Shield}
          title="Security"
          description="Manage your account security"
        >
          <div className="space-y-4">
            <SettingToggle
              label="Two-Factor Authentication"
              description="Add an extra layer of security to your account"
              checked={settings.twoFactorEnabled}
              onChange={(checked) => setSettings({ ...settings, twoFactorEnabled: checked })}
            />
            <SettingToggle
              label="API Access"
              description="Enable API access for automated submissions"
              checked={settings.apiAccessEnabled}
              onChange={(checked) => setSettings({ ...settings, apiAccessEnabled: checked })}
            />
            <div className="pt-4 border-t border-gray-200">
              <button className="text-sm text-blue-600 hover:text-blue-700 font-medium">
                Change Password
              </button>
            </div>
          </div>
        </SettingsSection>

        {/* Payment Settings */}
        <SettingsSection
          icon={CreditCard}
          title="Payment Information"
          description="Manage how you receive rewards"
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Payment Method
              </label>
              <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                <option>PayPal</option>
                <option>Bank Transfer</option>
                <option>Cryptocurrency</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                PayPal Email
              </label>
              <input
                type="email"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="paypal@example.com"
              />
            </div>
          </div>
        </SettingsSection>

        {/* Save Button */}
        <div className="flex justify-end">
          <button
            onClick={handleSave}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center"
          >
            <Save className="h-5 w-5 mr-2" />
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
}

interface SettingsSectionProps {
  icon: React.ElementType;
  title: string;
  description: string;
  children: React.ReactNode;
}

function SettingsSection({ icon: Icon, title, description, children }: SettingsSectionProps) {
  return (
    <div className="bg-white rounded-lg shadow">
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center">
          <div className="p-2 bg-blue-50 rounded-lg">
            <Icon className="h-5 w-5 text-blue-600" />
          </div>
          <div className="ml-4">
            <h2 className="text-lg font-semibold text-gray-900">{title}</h2>
            <p className="text-sm text-gray-600">{description}</p>
          </div>
        </div>
      </div>
      <div className="px-6 py-6">
        {children}
      </div>
    </div>
  );
}

interface SettingToggleProps {
  label: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}

function SettingToggle({ label, description, checked, onChange }: SettingToggleProps) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex-1">
        <div className="text-sm font-medium text-gray-900">{label}</div>
        <div className="text-xs text-gray-600">{description}</div>
      </div>
      <button
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
          checked ? 'bg-blue-600' : 'bg-gray-200'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            checked ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
    </div>
  );
}
