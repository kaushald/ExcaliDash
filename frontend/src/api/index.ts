import axios from "axios";
import type { Drawing, Collection } from "../types";

export const API_URL = import.meta.env.VITE_API_URL || "/api";

export const api = axios.create({
  baseURL: API_URL,
  withCredentials: true, // Send cookies with requests
});

// Handle 401 responses globally - redirect to login
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Redirect to login if not already there
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

// --- Auth ---

export const login = async (username: string, password: string) => {
  const response = await api.post<{ success: boolean }>("/auth/login", {
    username,
    password,
  });
  return response.data;
};

export const logout = async () => {
  const response = await api.post<{ success: boolean }>("/auth/logout");
  return response.data;
};

export const checkAuth = async (): Promise<boolean> => {
  try {
    const response = await api.get<{ authenticated: boolean }>("/auth/check");
    return response.data.authenticated;
  } catch {
    return false;
  }
};

const coerceTimestamp = (value: string | number | Date): number => {
  if (typeof value === "number") return value;
  if (value instanceof Date) return value.getTime();
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Date.now() : parsed;
};

const deserializeDrawing = (drawing: any): Drawing => ({
  ...drawing,
  createdAt: coerceTimestamp(drawing.createdAt),
  updatedAt: coerceTimestamp(drawing.updatedAt),
});

export const getDrawings = async (
  search?: string,
  collectionId?: string | null
) => {
  const params: any = {};
  if (search) params.search = search;
  if (collectionId !== undefined)
    params.collectionId = collectionId === null ? "null" : collectionId;
  const response = await api.get<Drawing[]>("/drawings", { params });
  return response.data.map(deserializeDrawing);
};

export const getDrawing = async (id: string) => {
  const response = await api.get<Drawing>(`/drawings/${id}`);
  return deserializeDrawing(response.data);
};

export const createDrawing = async (
  name?: string,
  collectionId?: string | null
) => {
  const response = await api.post<{ id: string }>("/drawings", {
    name,
    collectionId,
  });
  return response.data;
};

export const updateDrawing = async (id: string, data: Partial<Drawing>) => {
  const response = await api.put<{ success: true }>(`/drawings/${id}`, data);
  return response.data;
};

export const deleteDrawing = async (id: string) => {
  const response = await api.delete<{ success: true }>(`/drawings/${id}`);
  return response.data;
};

export const duplicateDrawing = async (id: string) => {
  const response = await api.post<Drawing>(`/drawings/${id}/duplicate`);
  return deserializeDrawing(response.data);
};

export const getCollections = async () => {
  const response = await api.get<Collection[]>("/collections");
  return response.data;
};

export const createCollection = async (name: string) => {
  const response = await api.post<Collection>("/collections", { name });
  return response.data;
};

export const updateCollection = async (id: string, name: string) => {
  const response = await api.put<{ success: true }>(`/collections/${id}`, {
    name,
  });
  return response.data;
};

export const deleteCollection = async (id: string) => {
  const response = await api.delete<{ success: true }>(`/collections/${id}`);
  return response.data;
};

// --- Library ---

export const getLibrary = async () => {
  const response = await api.get<{ items: any[] }>("/library");
  return response.data.items;
};

export const updateLibrary = async (items: any[]) => {
  const response = await api.put<{ items: any[] }>("/library", { items });
  return response.data.items;
};
