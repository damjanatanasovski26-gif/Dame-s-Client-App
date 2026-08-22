function dsStripFlashParams() {
  // Flash messages (msg=/err=) are delivered via redirect query params. If we
  // leave them in the URL, a plain browser refresh re-requests that same URL
  // and Flask shows the same "X updated" message again. The message has
  // already been rendered into the page at this point, so it's safe to strip
  // the params from the address bar right after.
  const url = new URL(window.location.href);
  if (url.searchParams.has("msg") || url.searchParams.has("err")) {
    url.searchParams.delete("msg");
    url.searchParams.delete("err");
    window.history.replaceState(window.history.state, "", url.toString());
  }
}
dsStripFlashParams();
window.addEventListener("ds:content-updated", dsStripFlashParams);

(function () {
  // Opens: <button data-ds-modal-open="modal-id">
  // Closes: <button data-ds-modal-close> inside the modal, backdrop click, or Escape.
  document.addEventListener("click", function (event) {
    const opener = event.target.closest("[data-ds-modal-open]");
    if (opener) {
      const modal = document.getElementById(opener.getAttribute("data-ds-modal-open"));
      if (modal) modal.classList.add("is-open");
      return;
    }

    const closer = event.target.closest("[data-ds-modal-close]");
    if (closer) {
      const modal = closer.closest("[data-ds-modal]");
      if (modal) modal.classList.remove("is-open");
      return;
    }

    if (event.target.matches("[data-ds-modal].is-open")) {
      event.target.classList.remove("is-open");
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    document.querySelectorAll("[data-ds-modal].is-open").forEach(function (modal) {
      modal.classList.remove("is-open");
    });
  });
})();

(function () {
  // Segmented sub-nav: <button data-ds-segment="panel-id"> toggles <div data-ds-segment-panel="panel-id" hidden>
  // Delegated at document level (not bound per-element) so it keeps working after AJAX content swaps.
  document.addEventListener("click", function (event) {
    const btn = event.target.closest("[data-ds-segment]");
    if (!btn) return;
    const group = btn.closest("[data-ds-segmented]");
    if (!group) return;
    const scope = group.closest("[data-ds-segment-scope]") || document;
    const target = btn.getAttribute("data-ds-segment");
    group.querySelectorAll("[data-ds-segment]").forEach(function (b) {
      b.classList.toggle("active", b === btn);
    });
    scope.querySelectorAll("[data-ds-segment-panel]").forEach(function (panel) {
      panel.hidden = panel.getAttribute("data-ds-segment-panel") !== target;
    });
  });
})();

function dsInitAlerts(root) {
  (root || document).querySelectorAll("[data-ds-alert]").forEach(function (alertEl) {
    if (alertEl.dataset.dsAlertArmed) return;
    alertEl.dataset.dsAlertArmed = "1";
    window.setTimeout(function () {
      alertEl.style.transition = "opacity 220ms ease, transform 220ms ease";
      alertEl.style.opacity = "0";
      alertEl.style.transform = "translateY(-6px)";
      window.setTimeout(function () { alertEl.remove(); }, 240);
    }, 4200);
  });
}
dsInitAlerts(document);

// Custom file input: <input class="ds-file-field__input"> + sibling [data-ds-file-name].
document.addEventListener("change", function (event) {
  const input = event.target.closest(".ds-file-field__input");
  if (!input) return;
  const field = input.closest(".ds-file-field");
  const nameEl = field && field.querySelector("[data-ds-file-name]");
  if (!nameEl) return;
  const files = input.files;
  if (!files || !files.length) {
    nameEl.textContent = "No file chosen";
  } else if (files.length === 1) {
    nameEl.textContent = files[0].name;
  } else {
    nameEl.textContent = files.length + " files selected";
  }
});

/* ==========================================================================
   Custom confirm modal — replaces window.confirm().
   Usage: <form data-ds-confirm="Delete this goal?"> or
          <button data-ds-confirm="Delete this?"> (for non-form actions)
   ========================================================================== */
var dsConfirmPendingAction = null;

function dsShowConfirm(message, onConfirm) {
  const modal = document.getElementById("dsConfirmModal");
  const msgEl = document.getElementById("dsConfirmMessage");
  if (!modal || !msgEl) { onConfirm(); return; }
  msgEl.textContent = message || "This action cannot be undone.";
  dsConfirmPendingAction = onConfirm;
  modal.classList.add("is-open");
}

document.addEventListener("click", function (event) {
  if (event.target.closest("#dsConfirmCancel") || (event.target.id === "dsConfirmModal")) {
    dsConfirmPendingAction = null;
    return;
  }
  if (event.target.closest("#dsConfirmOk")) {
    const action = dsConfirmPendingAction;
    dsConfirmPendingAction = null;
    document.getElementById("dsConfirmModal")?.classList.remove("is-open");
    if (action) action();
  }
});

/* ==========================================================================
   Generic AJAX navigation — no backend changes needed.
   Server routes already redirect back to a normal HTML page after a POST;
   we just fetch that same round-trip instead of letting the browser do a
   full navigation, then swap #dsPageRoot's content in place.

   - Every <form method="post"> is intercepted automatically.
   - Links opt in explicitly via data-ds-nav (file-download links like CSV
     export/backup are left as normal navigation on purpose).
   - data-ds-confirm on a form/button shows the custom modal first.
   ========================================================================== */
function dsRunScripts(root) {
  root.querySelectorAll("script").forEach(function (old) {
    const fresh = document.createElement("script");
    for (const attr of old.attributes) fresh.setAttribute(attr.name, attr.value);
    fresh.textContent = old.textContent;
    old.replaceWith(fresh);
  });
}

function dsSetLoading(isLoading) {
  const root = document.getElementById("dsPageRoot");
  if (root) root.classList.toggle("ds-loading", isLoading);
}

function dsSwapPage(html, finalUrl) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  const newRoot = doc.getElementById("dsPageRoot");
  const root = document.getElementById("dsPageRoot");
  if (!newRoot || !root) {
    window.location.href = finalUrl;
    return;
  }
  document.title = doc.title;
  document.body.className = doc.body.className;
  root.innerHTML = newRoot.innerHTML;
  if (finalUrl && finalUrl !== window.location.href) {
    window.history.pushState({ dsAjax: true }, "", finalUrl);
  }
  // A real browser navigation always starts scrolled to the top; since this
  // is just an innerHTML swap, the browser has no reason to reset scroll on
  // its own, so whatever position you were at on the previous page carries
  // over (e.g. landing mid-list after opening a client from a scrolled
  // dashboard).
  window.scrollTo(0, 0);
  dsRunScripts(root);
  dsInitAlerts(root);
  window.dispatchEvent(new CustomEvent("ds:content-updated"));
}

function dsNavigate(url, fetchOptions) {
  dsSetLoading(true);
  return fetch(url, Object.assign({ credentials: "same-origin" }, fetchOptions))
    .then(function (resp) {
      if (!resp.ok && resp.status >= 500) throw new Error("Server error");
      return resp.text().then(function (html) {
        dsSwapPage(html, resp.url);
      });
    })
    .catch(function () {
      window.location.href = url;
    })
    .finally(function () {
      dsSetLoading(false);
    });
}

function dsSubmitFormAjax(form) {
  const formData = new FormData(form);
  const method = (form.getAttribute("method") || "GET").toUpperCase();
  const url = form.getAttribute("action") || window.location.href;
  if (method === "GET") {
    const params = new URLSearchParams(formData);
    dsNavigate(url + (url.includes("?") ? "&" : "?") + params.toString(), { method: "GET" });
  } else {
    dsNavigate(url, { method: method, body: formData });
  }
}

document.addEventListener("submit", function (event) {
  if (event.defaultPrevented) return;
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (form.hasAttribute("data-no-ajax")) return;

  const confirmMsg = form.getAttribute("data-ds-confirm");
  if (confirmMsg) {
    event.preventDefault();
    dsShowConfirm(confirmMsg, function () { dsSubmitFormAjax(form); });
    return;
  }

  event.preventDefault();
  dsSubmitFormAjax(form);
});

document.addEventListener("click", function (event) {
  const link = event.target.closest("[data-ds-nav]");
  if (!link) return;
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
  event.preventDefault();
  dsNavigate(link.getAttribute("href"), { method: "GET" });
});

window.addEventListener("popstate", function () {
  dsNavigate(window.location.href, { method: "GET" });
});
