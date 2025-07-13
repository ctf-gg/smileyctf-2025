const url = new URL(window.location.href);
const host = url.searchParams.get("hostname");
const reason = url.searchParams.get("reason");
document.getElementById("hostname").textContent = host;
document.getElementById("reason").textContent = reason;