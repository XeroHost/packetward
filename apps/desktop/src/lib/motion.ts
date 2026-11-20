// SPDX-License-Identifier: GPL-3.0-or-later
// Motion vocabulary of the UI (docs/DESIGN.md "Motion"). Springs for things that move with the
// user, short ease-out tweens for things that appear. Transform and opacity only: it has to be
// smooth over RDP on a VPS without a GPU.
import type { Transition } from 'motion-v'

/** Page changes and panels sliding in: quick, no bounce. */
export const springPage: Transition = { type: 'spring', stiffness: 420, damping: 38, mass: 0.9 }

/** Small things that follow the pointer: the active-page marker, toggles. */
export const springSnappy: Transition = { type: 'spring', stiffness: 520, damping: 40, mass: 0.7 }

/** Dialogs and popovers growing from their origin. */
export const springDialog: Transition = { type: 'spring', stiffness: 360, damping: 30, mass: 0.8 }

/** Exits are quicker than entrances. */
export const exitFast: Transition = { duration: 0.12, ease: [0.4, 0, 1, 1] }

/** Stagger between rows of a list as it appears. */
export const LIST_STAGGER = 0.025
