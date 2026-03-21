(function versionFooterBootstrap() {
  var FOOTER_ID = "gpt-rag-version-footer";
  var FOOTER_TEXT_ID = "gpt-rag-version-footer-text";
  var RESERVE_PX = 28;

  var cachedData = null;
  var footerEnabled = false;
  var wrapperCache = null;

  /* ── Find the compositor wrapper ─────────────────── */

  /**
   * Walk up from #chat-input to find the compositor wrapper div.
   * The wrapper is a flex child of the main page flex column,
   * next to the scroll area sibling (which has flex-grow).
   * Adding margin-bottom to this element pushes the compositor up,
   * creating space for the fixed footer at the viewport bottom.
   */
  function findCompositorWrapper() {
    var input = document.getElementById("chat-input");
    if (!input) return null;

    var candidate = null;
    var el = input;
    for (var i = 0; i < 8 && el && el.parentElement; i++) {
      el = el.parentElement;
      var parent = el.parentElement;
      if (!parent || parent === document.body) continue;

      var ps = getComputedStyle(parent);
      if (ps.display !== "flex" || ps.flexDirection !== "column") continue;

      for (var j = 0; j < parent.children.length; j++) {
        var sibling = parent.children[j];
        if (sibling !== el && getComputedStyle(sibling).flexGrow !== "0") {
          candidate = el;
          break;
        }
      }
    }
    return candidate;
  }

  function getWrapper() {
    if (wrapperCache && wrapperCache.isConnected) return wrapperCache;
    wrapperCache = findCompositorWrapper();
    return wrapperCache;
  }

  function ensureSpacing() {
    var w = getWrapper();
    if (!w) return;
    if (w.style.marginBottom !== RESERVE_PX + "px") {
      w.style.marginBottom = RESERVE_PX + "px";
    }
  }

  /* ── Footer element helpers ──────────────────────── */

  function createLabel(text) {
    var label = document.createElement("span");
    label.className = "version-label";
    label.textContent = text;
    return label;
  }

  function createDivider() {
    var divider = document.createElement("span");
    divider.className = "version-divider";
    divider.setAttribute("aria-hidden", "true");
    return divider;
  }

  function renderTextNode(target, leftValue, rightValue) {
    target.replaceChildren(
      createLabel("gpt-rag"),
      document.createTextNode(" " + leftValue + " "),
      createDivider(),
      document.createTextNode(" "),
      createLabel("gpt-rag-ui"),
      document.createTextNode(" " + rightValue)
    );
  }

  function ensureFooter() {
    var footer = document.getElementById(FOOTER_ID);
    if (footer) return footer;

    footer = document.createElement("div");
    footer.id = FOOTER_ID;
    footer.className = "version-footer";

    var text = document.createElement("p");
    text.id = FOOTER_TEXT_ID;
    text.className = "version-footer-text";
    footer.appendChild(text);

    document.body.appendChild(footer);
    return footer;
  }

  function removeFooter() {
    var el = document.getElementById(FOOTER_ID);
    if (el) el.remove();
  }

  function renderFooterContent() {
    if (!footerEnabled || !cachedData) return;
    var footer = ensureFooter();
    var text = footer.querySelector("#" + FOOTER_TEXT_ID);
    if (!text) return;

    renderTextNode(
      text,
      cachedData.gpt_rag_release || "gpt-rag release information is missing",
      cachedData.gpt_rag_ui_release || "gpt-rag-ui release information is missing"
    );
    ensureSpacing();
  }

  /* ── Fetch version data ──────────────────────────── */

  async function loadVersionFooter() {
    var fallback = {
      gpt_rag_release: "gpt-rag release information is missing",
      gpt_rag_ui_release: "gpt-rag-ui release information is missing",
    };

    try {
      var response = await fetch("/version-footer", { cache: "no-store" });
      if (!response.ok) {
        cachedData = fallback;
        footerEnabled = true;
        renderFooterContent();
        return;
      }

      var contentType = response.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/json")) {
        cachedData = fallback;
        footerEnabled = true;
        renderFooterContent();
        return;
      }

      var data = await response.json();
      if (!data || data.show_release_footer === false) {
        footerEnabled = false;
        removeFooter();
        return;
      }

      cachedData = data;
      footerEnabled = true;
      renderFooterContent();
    } catch (_error) {
      cachedData = fallback;
      footerEnabled = true;
      renderFooterContent();
    }
  }

  /* ── Boot ─────────────────────────────────────────── */

  function boot() {
    loadVersionFooter();

    var rafId = null;
    var scheduleSync = function () {
      if (rafId) return;
      rafId = requestAnimationFrame(function () {
        rafId = null;
        if (!footerEnabled) return;
        ensureSpacing();
      });
    };

    var observer = new MutationObserver(scheduleSync);
    observer.observe(document.body, { childList: true, subtree: true });
    window.addEventListener("resize", scheduleSync);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
