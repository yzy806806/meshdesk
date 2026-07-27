/**
 * anim.js — Thin anime.js v4 wrapper with semantic, Promise-returning helpers.
 * Centralizes animation defaults and RAF lifecycle so call sites stay short.
 * Load AFTER anime.min.js, BEFORE app scripts.
 *
 * @module MeshAnim
 * @requires anime (global, from anime.min.js v4)
 * @see https://animejs.com
 */
(function () {
  'use strict';

  /** Default animation parameters for all helpers. */
  var DEFAULTS = { duration: 400, ease: 'out(3)' }; // easeOutCubic

  /** Tracks in-flight animations for cancellation. */
  var _active = new Set();

  /**
   * Core runner: creates an anime.animate() instance, tracks it, returns a
   * Promise that resolves on completion. User-supplied onComplete is preserved.
   *
   * @private
   * @param {string|Element|NodeList|Array} target - CSS selector or element(s).
   * @param {Object} props - Animation properties (opacity, translateY, …).
   * @param {Object} [opts] - Extra options merged on top of DEFAULTS.
   * @returns {Promise<void>}
   */
  function _run(target, props, opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      var userCb = opts.onComplete;
      var anim = anime.animate(
        typeof target === 'string' ? document.querySelectorAll(target) : target,
        Object.assign({}, DEFAULTS, props, opts, {
          onComplete: function (a) {
            _active.delete(a);
            if (userCb) userCb(a);
            resolve();
          }
        })
      );
      _active.add(anim);
    });
  }

  /**
   * Fade elements in from opacity 0 → 1.
   * @param {string|Element|NodeList|Array} target - Elements to animate.
   * @param {Object} [opts] - Override defaults (duration, ease, delay, …).
   * @returns {Promise<void>} Resolves when the animation completes.
   */
  function fadeIn(target, opts) {
    return _run(target, { opacity: [0, 1] }, opts);
  }

  /**
   * Fade elements out from current opacity → 0.
   * @param {string|Element|NodeList|Array} target - Elements to animate.
   * @param {Object} [opts] - Override defaults.
   * @returns {Promise<void>} Resolves when the animation completes.
   */
  function fadeOut(target, opts) {
    return _run(target, { opacity: [1, 0] }, opts);
  }

  /**
   * Slide elements in from 20px below + fade in.
   * @param {string|Element|NodeList|Array} target - Elements to animate.
   * @param {Object} [opts] - Override defaults; set translateY/translateX for direction.
   * @returns {Promise<void>} Resolves when the animation completes.
   */
  function slideIn(target, opts) {
    return _run(target, { opacity: [0, 1], translateY: [20, 0] }, opts);
  }

  /**
   * Staggered appear: fade + slight slide with per-element delay via anime.stagger().
   * @param {string|Element|NodeList|Array} target - Elements to animate.
   * @param {number} [staggerDelay=50] - Delay between each element in ms.
   * @param {Object} [opts] - Override defaults.
   * @returns {Promise<void>} Resolves when the last element finishes.
   */
  function staggeredAppear(target, staggerDelay, opts) {
    if (staggerDelay === undefined) staggerDelay = 50;
    return _run(target, {
      opacity: [0, 1],
      translateY: [12, 0],
      delay: anime.stagger(staggerDelay)
    }, opts);
  }

  /**
   * Cancel all in-flight animations and release RAF callbacks.
   * Pending Promises remain unresolved (callers should not await after cancel).
   * @returns {void}
   */
  function cancelAll() {
    _active.forEach(function (a) { a.cancel(); });
    _active.clear();
  }

  // Expose on window for non-module pages
  window.MeshAnim = {
    DEFAULTS: DEFAULTS,
    fadeIn: fadeIn,
    fadeOut: fadeOut,
    slideIn: slideIn,
    staggeredAppear: staggeredAppear,
    cancelAll: cancelAll
  };
})();
