const $ = (selector) => document.querySelector(selector);

const state = {
  user: null,
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });

  const type = response.headers.get("Content-Type") || "";
  const payload = type.includes("application/json") ? await response.json() : await response.text();

  if (!response.ok) {
    const message = payload && payload.message ? payload.message : "Request failed";
    throw new Error(message);
  }

  return payload;
}

function toast(message, isError = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", isError);
  node.classList.add("show");
  setTimeout(() => node.classList.remove("show"), 2600);
}

function setUser(user) {
  state.user = user;
  $("#session").textContent = user ? `Signed in as ${user.username}` : "Signed out";
}

async function refreshMe() {
  try {
    const payload = await api("/api/me");
    setUser(payload.user);
    await loadCards();
  } catch {
    setUser(null);
    $("#cards").innerHTML = "";
  }
}

async function loadCards() {
  const payload = await api("/api/cards");
  renderCards(payload.cards);
}

function renderCards(cards) {
  const root = $("#cards");
  if (!cards.length) {
    root.innerHTML = `<p class="small">No cards yet.</p>`;
    return;
  }

  root.innerHTML = cards.map((card) => {
    const receipt = card.receipt_code
      ? `<span class="receipt">Receipt: /api/cards/${card.id}/receipt?code=${card.receipt_code}</span>`
      : "";
    const owner = card.owner ? `Owner: ${escapeHtml(card.owner)} · ` : "";
    return `
      <article class="card">
        <h3>${escapeHtml(card.title)}</h3>
        <div class="meta">${owner}Card #${card.id} · ${escapeHtml(card.created_at || "")}</div>
        <div class="preview">${escapeHtml(card.preview || card.body || "")}</div>
        ${receipt}
      </article>
    `;
  }).join("");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const payload = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#username").value,
        password: $("#password").value,
      }),
    });
    setUser(payload.user);
    await loadCards();
    toast("Logged in");
  } catch (error) {
    toast(error.message, true);
  }
});

$("#register").addEventListener("click", async () => {
  try {
    await api("/api/register", {
      method: "POST",
      body: JSON.stringify({
        username: $("#username").value,
        email: $("#email").value,
        password: $("#password").value,
      }),
    });
    toast("Account created");
  } catch (error) {
    toast(error.message, true);
  }
});

$("#logout").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
  } finally {
    setUser(null);
    $("#cards").innerHTML = "";
    toast("Logged out");
  }
});

$("#card-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/cards", {
      method: "POST",
      body: JSON.stringify({
        title: $("#title").value,
        body: $("#body").value,
      }),
    });
    $("#title").value = "";
    $("#body").value = "";
    await loadCards();
    toast("Card created");
  } catch (error) {
    toast(error.message, true);
  }
});

$("#refresh").addEventListener("click", () => loadCards().catch((error) => toast(error.message, true)));

$("#run-search").addEventListener("click", async () => {
  try {
    const q = encodeURIComponent($("#search").value);
    const payload = await api(`/api/cards/search?q=${q}`);
    renderCards(payload.cards);
  } catch (error) {
    toast(error.message, true);
  }
});

document.querySelectorAll(".library-link").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      const response = await fetch(`/api/library?doc=${encodeURIComponent(button.dataset.doc)}`, {
        credentials: "same-origin",
      });
      if (!response.ok) {
        throw new Error("Document is not available");
      }
      $("#library-output").textContent = await response.text();
    } catch (error) {
      toast(error.message, true);
    }
  });
});

refreshMe();
