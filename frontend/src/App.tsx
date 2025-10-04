import React from "react";

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = React.useState(false);
  const [currentPage, setCurrentPage] = React.useState<"login" | "register">(
    "login"
  );
  const [user, setUser] = React.useState<any>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  const handleLogin = async (email: string, password: string) => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("http://localhost:3001/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
      if (response.ok) {
        setUser(data.data.user);
        setIsAuthenticated(true);
        localStorage.setItem("token", data.data.token);
      } else {
        setError(data.message || "Login failed");
      }
    } catch (err) {
      setError("Failed to connect to server");
    }
    setLoading(false);
  };

  const handleRegister = async (formData: any) => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("http://localhost:3001/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (response.ok) {
        setCurrentPage("login");
        alert("Registration successful! Please login.");
      } else {
        setError(
          data.errors
            ? data.errors.map((e: any) => e.message).join(", ")
            : data.message || "Registration failed"
        );
      }
    } catch (err) {
      setError("Failed to connect to server");
    }
    setLoading(false);
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUser(null);
    localStorage.removeItem("token");
    setCurrentPage("login");
  };

  if (isAuthenticated) {
    return <Dashboard user={user} onLogout={handleLogout} />;
  }

  if (currentPage === "register") {
    return (
      <RegisterForm
        onRegister={handleRegister}
        onSwitchToLogin={() => setCurrentPage("login")}
        error={error}
        loading={loading}
      />
    );
  }

  return (
    <LoginForm
      onLogin={handleLogin}
      onSwitchToRegister={() => setCurrentPage("register")}
      error={error}
      loading={loading}
    />
  );
};

const LoginForm: React.FC<{
  onLogin: (email: string, password: string) => void;
  onSwitchToRegister: () => void;
  error: string;
  loading: boolean;
}> = ({ onLogin, onSwitchToRegister, error, loading }) => {
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
      }}
    >
      <div
        style={{
          backgroundColor: "white",
          padding: "40px",
          borderRadius: "16px",
          boxShadow: "0 20px 60px rgba(0,0,0,0.3)",
          width: "400px",
        }}
      >
        <h1
          style={{ textAlign: "center", marginBottom: "10px", color: "#333" }}
        >
          🔐 Secure Finance
        </h1>
        <p style={{ textAlign: "center", color: "#666", marginBottom: "30px" }}>
          Login to your account
        </p>
        {error && (
          <div
            style={{
              backgroundColor: "#fee",
              color: "#c33",
              padding: "12px",
              borderRadius: "8px",
              marginBottom: "20px",
              textAlign: "center",
              fontSize: "14px",
            }}
          >
            {error}
          </div>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onLogin(email, password);
          }}
        >
          <div style={{ marginBottom: "20px" }}>
            <label
              style={{
                display: "block",
                marginBottom: "8px",
                color: "#555",
                fontWeight: "500",
              }}
            >
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              style={{
                width: "100%",
                padding: "12px",
                border: "2px solid #e0e0e0",
                borderRadius: "8px",
                fontSize: "16px",
                boxSizing: "border-box",
              }}
              placeholder="your@email.com"
            />
          </div>
          <div style={{ marginBottom: "25px" }}>
            <label
              style={{
                display: "block",
                marginBottom: "8px",
                color: "#555",
                fontWeight: "500",
              }}
            >
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                width: "100%",
                padding: "12px",
                border: "2px solid #e0e0e0",
                borderRadius: "8px",
                fontSize: "16px",
                boxSizing: "border-box",
              }}
              placeholder="••••••••"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              padding: "14px",
              backgroundColor: "#667eea",
              color: "white",
              border: "none",
              borderRadius: "8px",
              fontSize: "16px",
              fontWeight: "600",
              cursor: loading ? "not-allowed" : "pointer",
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>
        <p style={{ textAlign: "center", marginTop: "20px", color: "#666" }}>
          Don't have an account?{" "}
          <button
            onClick={onSwitchToRegister}
            style={{
              background: "none",
              border: "none",
              color: "#667eea",
              cursor: "pointer",
              textDecoration: "underline",
              fontSize: "14px",
            }}
          >
            Register
          </button>
        </p>
      </div>
    </div>
  );
};

const RegisterForm: React.FC<{
  onRegister: (data: any) => void;
  onSwitchToLogin: () => void;
  error: string;
  loading: boolean;
}> = ({ onRegister, onSwitchToLogin, error, loading }) => {
  const [username, setUsername] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [firstName, setFirstName] = React.useState("");
  const [lastName, setLastName] = React.useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onRegister({ username, email, password, firstName, lastName });
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
        padding: "20px",
      }}
    >
      <div
        style={{
          backgroundColor: "white",
          padding: "30px",
          borderRadius: "16px",
          boxShadow: "0 20px 60px rgba(0,0,0,0.3)",
          width: "100%",
          maxWidth: "450px",
          maxHeight: "90vh",
          overflowY: "auto",
        }}
      >
        <h1
          style={{
            textAlign: "center",
            marginBottom: "5px",
            color: "#333",
            fontSize: "24px",
          }}
        >
          🔐 Secure Finance
        </h1>
        <p
          style={{
            textAlign: "center",
            color: "#666",
            marginBottom: "20px",
            fontSize: "14px",
          }}
        >
          Create your account
        </p>
        {error && (
          <div
            style={{
              backgroundColor: "#fee",
              color: "#c33",
              padding: "10px",
              borderRadius: "8px",
              marginBottom: "15px",
              fontSize: "13px",
              wordBreak: "break-word",
            }}
          >
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "15px",
              marginBottom: "15px",
            }}
          >
            <div>
              <label
                style={{
                  display: "block",
                  marginBottom: "6px",
                  color: "#555",
                  fontWeight: "500",
                  fontSize: "14px",
                }}
              >
                First Name *
              </label>
              <input
                type="text"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                required
                style={{
                  width: "100%",
                  padding: "10px",
                  border: "2px solid #e0e0e0",
                  borderRadius: "8px",
                  fontSize: "14px",
                  boxSizing: "border-box",
                }}
                placeholder="John"
              />
            </div>
            <div>
              <label
                style={{
                  display: "block",
                  marginBottom: "6px",
                  color: "#555",
                  fontWeight: "500",
                  fontSize: "14px",
                }}
              >
                Last Name *
              </label>
              <input
                type="text"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                required
                style={{
                  width: "100%",
                  padding: "10px",
                  border: "2px solid #e0e0e0",
                  borderRadius: "8px",
                  fontSize: "14px",
                  boxSizing: "border-box",
                }}
                placeholder="Doe"
              />
            </div>
          </div>
          <div style={{ marginBottom: "15px" }}>
            <label
              style={{
                display: "block",
                marginBottom: "6px",
                color: "#555",
                fontWeight: "500",
                fontSize: "14px",
              }}
            >
              Username *
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength={3}
              style={{
                width: "100%",
                padding: "10px",
                border: "2px solid #e0e0e0",
                borderRadius: "8px",
                fontSize: "14px",
                boxSizing: "border-box",
              }}
              placeholder="johndoe"
            />
            <small style={{ color: "#888", fontSize: "11px" }}>
              3-30 chars, letters/numbers/_/-
            </small>
          </div>
          <div style={{ marginBottom: "15px" }}>
            <label
              style={{
                display: "block",
                marginBottom: "6px",
                color: "#555",
                fontWeight: "500",
                fontSize: "14px",
              }}
            >
              Email *
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              style={{
                width: "100%",
                padding: "10px",
                border: "2px solid #e0e0e0",
                borderRadius: "8px",
                fontSize: "14px",
                boxSizing: "border-box",
              }}
              placeholder="your@email.com"
            />
          </div>
          <div style={{ marginBottom: "20px" }}>
            <label
              style={{
                display: "block",
                marginBottom: "6px",
                color: "#555",
                fontWeight: "500",
                fontSize: "14px",
              }}
            >
              Password *
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              style={{
                width: "100%",
                padding: "10px",
                border: "2px solid #e0e0e0",
                borderRadius: "8px",
                fontSize: "14px",
                boxSizing: "border-box",
              }}
              placeholder="••••••••"
            />
            <small
              style={{
                color: "#888",
                fontSize: "11px",
                display: "block",
                marginTop: "4px",
              }}
            >
              Min 8 chars with: Uppercase, lowercase, number & special (@$!%*?&)
            </small>
          </div>
          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              padding: "12px",
              backgroundColor: "#667eea",
              color: "white",
              border: "none",
              borderRadius: "8px",
              fontSize: "16px",
              fontWeight: "600",
              cursor: loading ? "not-allowed" : "pointer",
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? "Creating account..." : "Register"}
          </button>
        </form>
        <p
          style={{
            textAlign: "center",
            marginTop: "15px",
            color: "#666",
            fontSize: "14px",
          }}
        >
          Already have an account?{" "}
          <button
            onClick={onSwitchToLogin}
            style={{
              background: "none",
              border: "none",
              color: "#667eea",
              cursor: "pointer",
              textDecoration: "underline",
              fontSize: "14px",
              fontWeight: "500",
            }}
          >
            Login
          </button>
        </p>
      </div>
    </div>
  );
};

const Dashboard: React.FC<{ user: any; onLogout: () => void }> = ({
  user,
  onLogout,
}) => {
  const [file, setFile] = React.useState<File | null>(null);
  const [uploading, setUploading] = React.useState(false);
  const [message, setMessage] = React.useState("");

  const handleFileUpload = async () => {
    if (!file) return;
    setUploading(true);
    setMessage("");
    try {
      const formData = new FormData();
      formData.append("file", file);
      const token = localStorage.getItem("token");
      const response = await fetch("http://localhost:3001/api/files/encrypt", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const data = await response.json();
      if (response.ok) {
        setMessage("✅ File encrypted successfully!");
        setFile(null);
      } else {
        setMessage("❌ " + (data.message || "Upload failed"));
      }
    } catch (err) {
      setMessage("❌ Failed to upload file");
    }
    setUploading(false);
  };

  return (
    <div style={{ minHeight: "100vh", backgroundColor: "#f5f7fa" }}>
      <div
        style={{
          backgroundColor: "white",
          padding: "20px 40px",
          boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div>
          <h1 style={{ margin: 0, color: "#333" }}>
            🔐 Secure Financial Data Platform
          </h1>
          <p style={{ margin: "5px 0 0 0", color: "#666" }}>
            Welcome, {user?.firstName || user?.username}!
          </p>
        </div>
        <button
          onClick={onLogout}
          style={{
            padding: "10px 20px",
            backgroundColor: "#dc3545",
            color: "white",
            border: "none",
            borderRadius: "8px",
            cursor: "pointer",
            fontWeight: "500",
          }}
        >
          Logout
        </button>
      </div>

      <div
        style={{ maxWidth: "1200px", margin: "0 auto", padding: "40px 20px" }}
      >
        <div
          style={{
            backgroundColor: "white",
            padding: "30px",
            borderRadius: "12px",
            boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
            marginBottom: "30px",
          }}
        >
          <h2 style={{ marginTop: 0, color: "#333" }}>
            📤 Upload & Encrypt File
          </h2>
          <p style={{ color: "#666", marginBottom: "20px" }}>
            Upload financial data files (Excel, PDF, CSV) for secure encryption
          </p>
          <div
            style={{
              display: "flex",
              gap: "15px",
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <input
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              style={{
                flex: 1,
                padding: "10px",
                border: "2px dashed #667eea",
                borderRadius: "8px",
                cursor: "pointer",
              }}
              accept=".xlsx,.xls,.pdf,.csv"
            />
            <button
              onClick={handleFileUpload}
              disabled={!file || uploading}
              style={{
                padding: "12px 30px",
                backgroundColor: file ? "#667eea" : "#ccc",
                color: "white",
                border: "none",
                borderRadius: "8px",
                cursor: file && !uploading ? "pointer" : "not-allowed",
                fontWeight: "600",
              }}
            >
              {uploading ? "Uploading..." : "Upload & Encrypt"}
            </button>
          </div>
          {message && (
            <div
              style={{
                marginTop: "15px",
                padding: "12px",
                backgroundColor: message.includes("✅") ? "#d4edda" : "#f8d7da",
                color: message.includes("✅") ? "#155724" : "#721c24",
                borderRadius: "8px",
              }}
            >
              {message}
            </div>
          )}
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: "20px",
          }}
        >
          <div
            style={{
              backgroundColor: "white",
              padding: "25px",
              borderRadius: "12px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
            }}
          >
            <div style={{ fontSize: "36px", marginBottom: "10px" }}>🔒</div>
            <h3 style={{ margin: "0 0 10px 0", color: "#333" }}>AES-256-GCM</h3>
            <p style={{ margin: 0, color: "#666", fontSize: "14px" }}>
              Military-grade encryption for all your financial data
            </p>
          </div>
          <div
            style={{
              backgroundColor: "white",
              padding: "25px",
              borderRadius: "12px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
            }}
          >
            <div style={{ fontSize: "36px", marginBottom: "10px" }}>📊</div>
            <h3 style={{ margin: "0 0 10px 0", color: "#333" }}>
              Data Processing
            </h3>
            <p style={{ margin: 0, color: "#666", fontSize: "14px" }}>
              Support for Excel, PDF, and CSV files
            </p>
          </div>
          <div
            style={{
              backgroundColor: "white",
              padding: "25px",
              borderRadius: "12px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
            }}
          >
            <div style={{ fontSize: "36px", marginBottom: "10px" }}>👥</div>
            <h3 style={{ margin: "0 0 10px 0", color: "#333" }}>
              Access Control
            </h3>
            <p style={{ margin: 0, color: "#666", fontSize: "14px" }}>
              Role-based permissions and audit logs
            </p>
          </div>
          <div
            style={{
              backgroundColor: "white",
              padding: "25px",
              borderRadius: "12px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
            }}
          >
            <div style={{ fontSize: "36px", marginBottom: "10px" }}>⚡</div>
            <h3 style={{ margin: "0 0 10px 0", color: "#333" }}>Real-time</h3>
            <p style={{ margin: 0, color: "#666", fontSize: "14px" }}>
              Instant encryption and health monitoring
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
