import { useEffect, useState } from 'react'
import { api, type Stats } from '@/lib/api'

const emptyStats: Stats = {
  total_requests: 0,
  blocked_requests: 0,
  challenged_requests: 0,
  logged_requests: 0,
  passed_requests: 0,
  avg_latency_us: 0,
}

export function useStats() {
  const [stats, setStats] = useState<Stats>(emptyStats)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true

    async function fetchStats() {
      try {
        const data = await api.getStats()
        if (active) {
          setStats(data)
          setLoading(false)
        }
      } catch {
        // keep previous stats on error
        if (active) setLoading(false)
      }
    }

    fetchStats()
    const interval = setInterval(() => {
      // Pause polling when tab is not visible
      if (document.hidden) return
      fetchStats()
    }, 5000)

    // Fetch fresh data when tab becomes visible again
    function onVisibilityChange() {
      if (!document.hidden && active) fetchStats()
    }
    document.addEventListener('visibilitychange', onVisibilityChange)

    return () => {
      active = false
      clearInterval(interval)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [])

  return { stats, loading }
}
