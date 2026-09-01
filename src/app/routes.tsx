import { createBrowserRouter, Navigate } from "react-router";
import TourismHome from "./pages/public/TourismHome";
import NotFound from "./pages/NotFound";

export const router = createBrowserRouter([
  { path: "/", Component: TourismHome },
  { path: "/explore", Component: TourismHome },
  { path: "/admin/login", element: <Navigate to="/" replace /> },
  { path: "/officer/*", element: <Navigate to="/" replace /> },
  { path: "/staff/*", element: <Navigate to="/" replace /> },
  { path: "*", Component: NotFound },
]);
