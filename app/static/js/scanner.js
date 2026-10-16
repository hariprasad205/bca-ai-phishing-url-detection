/**
 * Scanner Client-side Interaction & UI Handling
 */

document.addEventListener("DOMContentLoaded", function () {
  const scanForm = document.getElementById("urlScanForm");
  const scanBtn = document.getElementById("scanSubmitBtn");
  const btnSpinner = document.getElementById("scanSpinner");
  const btnText = document.getElementById("scanBtnText");

  if (scanForm && scanBtn) {
    scanForm.addEventListener("submit", function (e) {
      const urlInput = document.getElementById("urlInput");
      if (!urlInput || !urlInput.value.trim()) {
        e.preventDefault();
        alert("Please enter a URL to inspect.");
        return;
      }

      // Show spinner and disable button to prevent double-submissions
      if (btnSpinner) btnSpinner.classList.remove("d-none");
      if (btnText) btnText.textContent = "Extracting Features & Analyzing...";
      scanBtn.setAttribute("disabled", "disabled");
    });
  }
});
