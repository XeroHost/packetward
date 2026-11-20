// SPDX-License-Identifier: GPL-3.0-or-later
// Country names in the language of the UI, from the browser's own data (no extra dependency).

/** "US" -> "United States" / "Estados Unidos" / "Estados Unidos" (pt-BR), or the code itself. */
export function countryName(code: string, locale: string): string {
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(code.toUpperCase()) ?? code
  } catch {
    return code
  }
}
