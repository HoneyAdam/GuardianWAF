import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { api } from './api'

describe('api.request', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('makes GET request and returns JSON', async () => {
    const data = { total_requests: 100 }
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(data),
    } as Response)

    const result = await api.getStats()
    expect(result).toEqual(data)
    expect(fetch).toHaveBeenCalledWith('/api/v1/stats', expect.objectContaining({
      headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
    }))
  })

  it('throws on non-ok response with error body', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      json: () => Promise.resolve({ error: 'something broke' }),
    } as Response)

    await expect(api.getStats()).rejects.toThrow('something broke')
  })

  it('throws with statusText when error body is malformed', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      json: () => Promise.reject(new Error('not json')),
    } as Response)

    await expect(api.getStats()).rejects.toThrow('Bad Gateway')
  })

  it('sends POST with JSON body', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ status: 'ok' }),
    } as Response)

    await api.addIP('blacklist', '1.2.3.4')
    expect(fetch).toHaveBeenCalledWith('/api/v1/ipacl', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ list: 'blacklist', ip: '1.2.3.4' }),
    }))
  })

  it('sends PUT request', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ status: 'ok' }),
    } as Response)

    await api.updateConfig({ mode: 'monitor' })
    expect(fetch).toHaveBeenCalledWith('/api/v1/config', expect.objectContaining({
      method: 'PUT',
      body: JSON.stringify({ mode: 'monitor' }),
    }))
  })

  it('sends DELETE request', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ status: 'ok' }),
    } as Response)

    await api.deleteRule('rule-123')
    expect(fetch).toHaveBeenCalledWith('/api/v1/rules/rule-123', expect.objectContaining({
      method: 'DELETE',
    }))
  })

  it('appends query params for events', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ events: [], total: 0 }),
    } as Response)

    await api.getEvents({ action: 'block' })
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/events?action=block',
      expect.any(Object),
    )
  })

  it('works without query params for events', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ events: [], total: 0 }),
    } as Response)

    await api.getEvents()
    expect(fetch).toHaveBeenCalledWith('/api/v1/events', expect.any(Object))
  })
})
