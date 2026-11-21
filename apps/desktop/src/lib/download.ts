// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0

/**
 * Offers `content` to the user as a file (the webview shows its own save prompt). Returns
 * whether the download could be started. Nothing is sent anywhere: the text was already rendered by
 * the agent and stays in this process.
 */
export function downloadText(filename: string, content: string, mime = 'text/plain'): boolean {
  if (typeof document === 'undefined' || typeof URL === 'undefined') return false
  try {
    const url = URL.createObjectURL(new Blob([content], { type: `${mime};charset=utf-8` }))
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.rel = 'noopener'
    link.style.display = 'none'
    document.body.appendChild(link)
    link.click()
    link.remove()
    // Revoked a little later: some webviews read the blob after the click handler returns.
    setTimeout(() => URL.revokeObjectURL(url), 30_000)
    return true
  } catch {
    return false
  }
}

/** The media type that goes with an MTR export format. */
export function mimeOfExport(format: 'csv' | 'json' | 'text'): string {
  return format === 'csv' ? 'text/csv' : format === 'json' ? 'application/json' : 'text/plain'
}
