import { createBrowserRouter } from "react-router-dom";

import { AppShell } from "@/app/shell/AppShell";
import { DashboardPage } from "@/pages/DashboardPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppShell />,
    children: [
      {
        index: true,
        element: <DashboardPage />,
      },
    ],
  },
]);
