import { BrowserRouter, Routes, Route } from 'react-router'
import { Layout } from '@/components/layout/layout'
import DashboardPage from '@/pages/dashboard'
import ConfigPage from '@/pages/config'
import RoutingPage from '@/pages/routing'
import LogsPage from '@/pages/logs'
import RulesPage from '@/pages/rules'
import AIPage from '@/pages/ai'
import AlertingPage from '@/pages/alerting'

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="/routing" element={<RoutingPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/config" element={<ConfigPage />} />
          <Route path="/alerting" element={<AlertingPage />} />
          <Route path="/ai" element={<AIPage />} />
          <Route path="/logs" element={<LogsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
