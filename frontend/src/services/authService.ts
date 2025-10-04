// Placeholder API service - will be implemented when axios is installed
const API_BASE_URL =
  process.env.REACT_APP_API_URL || "http://localhost:5000/api";

export interface User {
  id: string;
  username: string;
  email: string;
  role: "user" | "analyst" | "admin" | "super_admin";
  isActive: boolean;
  createdAt: string;
  lastLogin: string;
}

export interface LoginResponse {
  success: boolean;
  message: string;
  data: {
    user: User;
    token: string;
  };
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  role?: string;
}

class AuthService {
  setAuthToken(token: string): void {
    // Placeholder - will set axios headers when axios is installed
    console.log("Setting auth token:", token.substring(0, 10) + "...");
  }

  clearAuthToken(): void {
    // Placeholder - will clear axios headers when axios is installed
    console.log("Clearing auth token");
  }

  async login(email: string, password: string): Promise<LoginResponse["data"]> {
    // Placeholder implementation
    throw new Error("Login functionality requires backend integration");
  }

  logout(): void {
    this.clearAuthToken();
    localStorage.removeItem("token");
    localStorage.removeItem("user");
  }

  isAuthenticated(): boolean {
    const token = localStorage.getItem("token");
    return !!token;
  }

  getCurrentUser(): User | null {
    try {
      const userData = localStorage.getItem("user");
      return userData ? JSON.parse(userData) : null;
    } catch (error) {
      console.error("Failed to parse stored user data:", error);
      return null;
    }
  }

  getToken(): string | null {
    return localStorage.getItem("token");
  }
}

// Export singleton instance
export const authService = new AuthService();
