(function versionFooterBootstrap() {
  const FOOTER_ID = "gpt-rag-version-footer";
  const FOOTER_TEXT_ID = "gpt-rag-version-footer-text";

  function createLabel(text) {
    const label = document.createElement("span");
    label.className = "version-label";
    label.textContent = text;
    return label;
  }

  function createDivider() {
    const divider = document.createElement("span");
    divider.className = "version-divider";
    divider.setAttribute("aria-hidden", "true");
    return divider;
  }

  function renderTextNode(target, leftValue, rightValue) {
    target.replaceChildren(
      createLabel("GPT Rag version:"),
      document.createTextNode(" " + leftValue + " "),
      createDivider(),
      document.createTextNode(" "),
      createLabel("GPT R UI version:"),
      document.createTextNode(" " + rightValue)
    );
  }

  function ensureFooter() {
    let footer = document.getElementById(FOOTER_ID);
    if (footer) {
      return footer;
    }

    footer = document.createElement("div");
    footer.id = FOOTER_ID;
    footer.className = "version-footer";

    const text = document.createElement("p");
    text.id = FOOTER_TEXT_ID;
    text.className = "version-footer-text";
    renderTextNode(text, "loading", "loading");

    footer.appendChild(text);
    document.body.appendChild(footer);
    document.body.classList.add("has-version-footer");

    return footer;
  }

  function removeFooter() {
    const footer = document.getElementById(FOOTER_ID);
    if (footer) {
      footer.remove();
    }
    document.body.classList.remove("has-version-footer");
  }

  function renderFooterText(data) {
    const footer = ensureFooter();
    const text = footer.querySelector("#" + FOOTER_TEXT_ID);
    if (!text) {
      return;
    }

    renderTextNode(
      text,
      data.gpt_rag_release || "gpt-rag release information is missing",
      data.gpt_rag_ui_release || "gpt-rag-ui release information is missing"
    );
  }

  async function loadVersionFooter() {
    try {
      const response = await fetch("/api/download/version-footer", { cache: "no-store" });
      if (!response.ok) {
        renderFooterText({
          gpt_rag_release: "gpt-rag release information is missing",
          gpt_rag_ui_release: "gpt-rag-ui release information is missing",
        });
        return;
      }

      const contentType = response.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/json")) {
        renderFooterText({
          gpt_rag_release: "gpt-rag release information is missing",
          gpt_rag_ui_release: "gpt-rag-ui release information is missing",
        });
        return;
      }

      const data = await response.json();
      if (!data || data.show_release_footer === false) {
        removeFooter();
        return;
      }

      renderFooterText(data);
    } catch (_error) {
      renderFooterText({
        gpt_rag_release: "gpt-rag release information is missing",
        gpt_rag_ui_release: "gpt-rag-ui release information is missing",
      });
    }
  }

  function boot() {
    loadVersionFooter();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
