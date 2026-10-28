const message = "Firebase Authentication has not been configured for this starter app.";

document.querySelectorAll("[data-auth-placeholder]").forEach((notice) => {
  notice.textContent = message;
});
