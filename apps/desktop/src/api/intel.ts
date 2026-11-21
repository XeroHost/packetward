// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for the threat intelligence methods (via the shell's `agent_call`).
import type { AbuseCheckView } from '@/types/generated/AbuseCheckView'
import type { AbuseStatusView } from '@/types/generated/AbuseStatusView'
import type { BlocklistsView } from '@/types/generated/BlocklistsView'
import type { GeoLookupResult } from '@/types/generated/GeoLookupResult'
import type { GeoStatusView } from '@/types/generated/GeoStatusView'
import { callAgent } from './call'

export type { AbuseCheckView, AbuseStatusView, BlocklistsView, GeoLookupResult, GeoStatusView }

export const geoStatus = () => callAgent<GeoStatusView>('intel.geo.status')
export const geoUpdate = () => callAgent<GeoStatusView>('intel.geo.update')
export const geoLookup = (addrs: string[]) => callAgent<GeoLookupResult>('intel.lookup', { addrs })
export const blocklists = () => callAgent<BlocklistsView>('intel.lists')
export const setListEnabled = (id: string, enabled: boolean) =>
  callAgent<BlocklistsView>('intel.list.enable', { id, enabled })
export const refreshList = (id: string) => callAgent<BlocklistsView>('intel.list.refresh', { id })
export const abuseStatus = () => callAgent<AbuseStatusView>('intel.abuse.status')
export const setAbuseKey = (key: string | null) =>
  callAgent<AbuseStatusView>('intel.abuse.set_key', key === null ? {} : { key })
export const abuseCheck = (addr: string) => callAgent<AbuseCheckView>('intel.abuse.check', { addr })
