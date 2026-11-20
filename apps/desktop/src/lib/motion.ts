// SPDX-License-Identifier: GPL-3.0-or-later
// Motion vocabulary of the UI (docs/DESIGN.md "Motion"). Springs for things that move with the
// user, short ease-out tweens for things that appear. Transform and opacity only: it has to be
// smooth over RDP on a VPS without a GPU.
import { animate, type Transition } from 'motion-v'

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

/**
 * Runs a motion animation for Vue's <Transition :css="false"> and always calls `done`: when the
 * animation ends, or after `safetyMs` if it never does (a window that is hidden or throttled does not
 * run animation frames, and a page change must never wait on a frame that does not come).
 */
export function runTransition(
  el: Element,
  keyframes: Record<string, unknown>,
  transition: Transition,
  done: () => void,
  safetyMs: number,
  settle?: () => void,
): void {
  let finished = false
  const controls = animate(el, keyframes, { ...transition, onComplete: () => finish() })
  const finish = (): void => {
    if (finished) return
    finished = true
    controls.stop()
    settle?.()
    done()
  }
  setTimeout(finish, safetyMs)
}

const reduced = (): boolean => document.documentElement.dataset.motion === 'reduced'

/**
 * Hooks for Vue's <Transition :css="false">: a panel rises in on a spring and drops out quickly.
 * Under "Reduce animations" (data-motion="reduced") nothing animates.
 */
export const panelTransition = {
  beforeEnter(el: Element): void {
    if (!reduced()) (el as HTMLElement).style.opacity = '0'
  },
  enter(el: Element, done: () => void): void {
    if (reduced()) return done()
    runTransition(el, { opacity: [0, 1], y: [8, 0] }, springPage, done, 900, () => {
      // Whatever happened to the animation, the page ends fully visible and in place.
      const style = (el as HTMLElement).style
      style.opacity = ''
      style.transform = ''
    })
  },
  leave(el: Element, done: () => void): void {
    if (reduced()) return done()
    runTransition(el, { opacity: 0, y: -3 }, exitFast, done, 250)
  },
}
