// Request body types
export interface SignupRequestBody {
  username: string;
  password: string;
  secretMessage: string;
}

export interface LoginRequestBody {
  username: string;
  password: string;
  algorithm?: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
}

// Response types
export interface UserResponse {
  username: string;
  secretMessage: string;
  createdAt: string;
}

export interface LoginResponse {
  user: {
    id: number;
    username: string;
    secretMessage: string;
  };
  token: string;
  algorithm: string;
  expiresIn: string;
}

export interface ApiResponse<T = any> {
  message?: string;
  error?: string;
  data?: T;
}

// Database types
export interface User {
  id: number;
  username: string;
  password_hash: string;
  secret_message: string;
  created_at: string;
}