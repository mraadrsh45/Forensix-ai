import axios from "axios";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 60000,
});

// Helper wrapper that tries backend API first, falling back gracefully if server isn't reached
export async function apiPost<T>(endpoint: string, payload: any, fallback: T): Promise<T> {
  try {
    const res = await apiClient.post(endpoint, payload);
    return res.data as T;
  } catch (err) {
    console.warn(`[ForensiX API] Calling fallback for ${endpoint}:`, err);
    return fallback;
  }
}

export async function apiGet<T>(endpoint: string, fallback: T): Promise<T> {
  try {
    const res = await apiClient.get(endpoint);
    return res.data as T;
  } catch (err) {
    console.warn(`[ForensiX API] Calling fallback for ${endpoint}:`, err);
    return fallback;
  }
}

export async function apiUploadFile<T>(endpoint: string, file: File, fallback: T): Promise<T> {
  try {
    const formData = new FormData();
    formData.append("file", file);
    const res = await apiClient.post(endpoint, formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    });
    return res.data as T;
  } catch (err) {
    console.warn(`[ForensiX API] Calling upload fallback for ${endpoint}:`, err);
    return fallback;
  }
}
