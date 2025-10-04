const App: React.FC = () => {
  return (
    <div style={{ 
      minHeight: '100vh', 
      display: 'flex', 
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '20px',
      fontFamily: 'Arial, sans-serif'
    }}>
      <h1 style={{ color: '#1976d2', marginBottom: '20px' }}>
        🔐 Secure Financial Data Platform
      </h1>
      
      <div style={{
        maxWidth: '600px',
        padding: '30px',
        backgroundColor: '#f5f5f5',
        borderRadius: '12px',
        textAlign: 'center'
      }}>
        <h2 style={{ marginBottom: '15px' }}>Frontend Coming Soon!</h2>
        
        <p style={{ marginBottom: '20px', lineHeight: '1.6' }}>
          The backend API is fully functional with enterprise-grade security features.
          Try our interactive demo to see all the capabilities!
        </p>
        
        <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
          <h3>🎮 Try the Interactive Demo</h3>
          <code style={{ 
            backgroundColor: '#f0f0f0', 
            padding: '10px', 
            borderRadius: '4px',
            display: 'block',
            margin: '10px 0'
          }}>
            cd backend && npm run demo
          </code>
        </div>
        
        <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px' }}>
          <h3>🔗 Available Features</h3>
          <ul style={{ textAlign: 'left', lineHeight: '1.8' }}>
            <li>🔒 AES-256-GCM File Encryption</li>
            <li>📊 Financial Data Processing (Excel, PDF, CSV)</li>
            <li>👥 Role-based Access Control</li>
            <li>📝 Comprehensive Audit Logging</li>
            <li>⚡ Real-time Health Monitoring</li>
            <li>🛡️ Enterprise Security Standards</li>
          </ul>
        </div>
        
        <p style={{ marginTop: '20px', color: '#666' }}>
          Backend server running at: <strong>http://localhost:5000</strong>
        </p>
      </div>
    </div>
  );
};

export default App;