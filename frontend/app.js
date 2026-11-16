/**
 * Payment Screenshot Scam Detector - Frontend Application
 * Configuration & Core Logic
 */

// 1. API Configuration (default: http://127.0.0.1:8000)
const API_URL = "";

// Allowed MIME types
const ALLOWED_MIME_TYPES = new Set(["image/jpeg", "image/png", "image/webp"]);
const MAX_DIMENSION = 1024;
const GAUGE_CIRCUMFERENCE = 251.32; // 2 * Math.PI * 40 (r=40 in SVG)

// DOM Elements
const fileInput = document.getElementById("fileInput");
const uploadZone = document.getElementById("uploadZone");
const uploadCard = document.getElementById("uploadCard");
const errorBanner = document.getElementById("errorBanner");
const errorText = document.getElementById("errorText");

const previewCard = document.getElementById("previewCard");
const previewTitle = document.getElementById("previewTitle");
const previewImage = document.getElementById("previewImage");
const scanLaser = document.getElementById("scanLaser");
const wakeupNotice = document.getElementById("wakeupNotice");
const resetBtn = document.getElementById("resetBtn");

const resultsSection = document.getElementById("resultsSection");
const verdictBadge = document.getElementById("verdictBadge");
const gaugeProgress = document.getElementById("gaugeProgress");
const gaugeNumber = document.getElementById("gaugeNumber");
const reasonText = document.getElementById("reasonText");

const fieldAmount = document.getElementById("fieldAmount");
const fieldTxId = document.getElementById("fieldTxId");
const fieldSender = document.getElementById("fieldSender");
const fieldReceiver = document.getElementById("fieldReceiver");
const fieldDateTime = document.getElementById("fieldDateTime");
const fieldAppName = document.getElementById("fieldAppName");

const redFlagsCard = document.getElementById("redFlagsCard");
const redFlagsList = document.getElementById("redFlagsList");
const adviceText = document.getElementById("adviceText");

// Initialize Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  setupUploadEvents();
  if (resetBtn) {
    resetBtn.addEventListener("click", resetApp);
  }
});

/**
 * Configure drag-and-drop and click upload events
 */
function setupUploadEvents() {
  uploadZone.addEventListener("click", () => fileInput.click());

  uploadZone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      handleSelectedFile(file);
    }
  });

  // Drag and drop events
  ["dragenter", "dragover"].forEach((eventName) => {
    uploadZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      uploadZone.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    uploadZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      uploadZone.classList.remove("drag-over");
    });
  });

  uploadZone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    const file = dt && dt.files && dt.files[0];
    if (file) {
      handleSelectedFile(file);
    }
  });
}

/**
 * Validate and process the chosen file
 */
async function handleSelectedFile(file) {
  hideError();

  // Validate MIME type (JPEG, PNG, WEBP only)
  if (!ALLOWED_MIME_TYPES.has(file.type)) {
    showError("Invalid file format. Please upload a JPEG, PNG, or WEBP image.");
    fileInput.value = "";
    return;
  }

  try {
    // Show preview and start scanning laser animation
    uploadCard.classList.add("hidden");
    previewCard.classList.remove("hidden");
    scanLaser.classList.remove("hidden");
    resetBtn.classList.add("hidden");
    previewTitle.textContent = "Scanning image...";
    resultsSection.classList.add("hidden");

    // Resize image in browser canvas (max side 1024px)
    const { blob: resizedBlob, dataUrl } = await resizeImage(file, MAX_DIMENSION);
    previewImage.src = dataUrl;

    // Send to API
    await analyzeImage(resizedBlob, file.name);
  } catch (err) {
    console.error(err);
    fileInput.value = "";
    previewImage.src = "";
    uploadCard.classList.remove("hidden");
    previewCard.classList.add("hidden");
    resultsSection.classList.add("hidden");
    scanLaser.classList.add("hidden");
    wakeupNotice.classList.add("hidden");
    showError(err.message || "Failed to process image.");
  }
}

/**
 * Resize image via HTML5 Canvas (longest side <= maxDimension)
 */
function resizeImage(file, maxDimension = 1024) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Unable to read the selected file."));
    reader.onload = (readerEvent) => {
      const img = new Image();
      img.onerror = () => reject(new Error("Failed to load image into browser."));
      img.onload = () => {
        let width = img.naturalWidth || img.width;
        let height = img.naturalHeight || img.height;

        if (width > maxDimension || height > maxDimension) {
          if (width > height) {
            height = Math.round((height * maxDimension) / width);
            width = maxDimension;
          } else {
            width = Math.round((width * maxDimension) / height);
            height = maxDimension;
          }
        }

        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");

        if (!ctx) {
          reject(new Error("Browser canvas context is unavailable."));
          return;
        }

        ctx.drawImage(img, 0, 0, width, height);

        const mimeType = file.type === "image/png" || file.type === "image/webp" ? file.type : "image/jpeg";
        canvas.toBlob(
          (blob) => {
            if (!blob) {
              reject(new Error("Failed to create image blob from canvas."));
              return;
            }
            resolve({ blob, dataUrl: canvas.toDataURL(mimeType, 0.92) });
          },
          mimeType,
          0.92
        );
      };
      img.src = readerEvent.target.result;
    };
    reader.readAsDataURL(file);
  });
}

/**
 * Send resized image to POST {API_URL}/analyze
 */
async function analyzeImage(blob, fileName) {
  // Wake-up notice timer (if request takes > 5 seconds)
  wakeupNotice.classList.add("hidden");
  const wakeupTimer = setTimeout(() => {
    wakeupNotice.textContent = "Server is waking up, please wait up to 30 seconds.";
    wakeupNotice.classList.remove("hidden");
  }, 5000);

  // 60-second request timeout using AbortController
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, 60000);

  // Send multipart/form-data with field "file" (and "image" for backend compatibility)
  const formData = new FormData();
  formData.append("file", blob, fileName);
  formData.append("image", blob, fileName);

  try {
    const response = await fetch(`${API_URL}/analyze`, {
      method: "POST",
      body: formData,
      signal: controller.signal,
    });

    clearTimeout(wakeupTimer);
    clearTimeout(timeoutId);
    wakeupNotice.classList.add("hidden");

    if (!response.ok) {
      const status = response.status;
      throw new Error(`Server error (${status}). Please try again.`);
    }

    const data = await response.json();
    renderAnalysisResult(data);
  } catch (err) {
    clearTimeout(wakeupTimer);
    clearTimeout(timeoutId);
    wakeupNotice.classList.add("hidden");

    // Log the error details with console.error
    console.error(err);

    let friendlyMessage = err.message;
    if (err.name === "AbortError" || controller.signal.aborted) {
      friendlyMessage = "The request took too long. Please try again.";
    } else if (
      err.name === "TypeError" ||
      (err.message && (
        err.message.includes("fetch") ||
        err.message.includes("Network") ||
        err.message.includes("network") ||
        err.message.includes("CORS") ||
        err.message.includes("cors")
      ))
    ) {
      friendlyMessage = "Cannot reach the server. Check that the backend is running.";
    }

    // Reset view to upload state so upload card is visible
    fileInput.value = "";
    previewImage.src = "";
    uploadCard.classList.remove("hidden");
    previewCard.classList.add("hidden");
    resultsSection.classList.add("hidden");
    scanLaser.classList.add("hidden");

    // Display error message under upload zone and keep it on screen
    showError(friendlyMessage);
  }
}

/**
 * Render the analysis results safely using textContent (preventing XSS)
 */
function renderAnalysisResult(data) {
  // Stop scanning laser
  scanLaser.classList.add("hidden");
  previewTitle.textContent = "Uploaded Screenshot";
  resetBtn.classList.remove("hidden");

  // 1. Verdict badge
  const verdict = data.verdict || "Unclear";
  verdictBadge.textContent = verdict;
  verdictBadge.className = "verdict-badge";

  let strokeColor = "#f59e0b"; // Default amber
  if (verdict === "Suspicious") {
    verdictBadge.classList.add("badge-suspicious");
    strokeColor = "#ef4444";
  } else if (verdict === "No red flags found") {
    verdictBadge.classList.add("badge-no-red-flags");
    strokeColor = "#06b6d4";
  } else {
    verdictBadge.classList.add("badge-unclear");
    strokeColor = "#f59e0b";
  }

  // 2. Animated Circular Risk Gauge
  const score = typeof data.risk_score === "number" ? Math.max(0, Math.min(100, data.risk_score)) : 50;
  animateRiskGauge(score, strokeColor);

  // 3. Explanation text (textContent only)
  reasonText.textContent = data.reason || "Analysis completed.";

  // 4. Extracted fields
  const fields = data.extracted_fields || {};
  renderField(fieldAmount, fields.amount);
  renderField(fieldTxId, fields.transaction_id);
  renderField(fieldSender, fields.sender);
  renderField(fieldReceiver, fields.receiver);
  renderField(fieldDateTime, fields.date_time);
  renderField(fieldAppName, fields.app_name);

  // 5. Red flags list with staggered fade-in
  renderRedFlags(data.red_flags);

  // 6. Advice text (textContent only)
  adviceText.textContent =
    data.advice ||
    "Please check your JazzCash/Easypaisa app or official SMS to confirm the payment. Do not trust screenshots alone.";

  // Display results section
  resultsSection.classList.remove("hidden");
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Animate Circular Risk Gauge
 */
function animateRiskGauge(targetScore, color) {
  gaugeProgress.style.stroke = color;

  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReducedMotion) {
    const offset = GAUGE_CIRCUMFERENCE * (1 - targetScore / 100);
    gaugeProgress.style.strokeDashoffset = offset.toString();
    gaugeNumber.textContent = targetScore.toString();
    return;
  }

  // Set offset transition
  const offset = GAUGE_CIRCUMFERENCE * (1 - targetScore / 100);
  gaugeProgress.style.strokeDashoffset = offset.toString();

  // Smooth number counter
  let current = 0;
  const duration = 1200; // ms
  const stepTime = 20; // ms
  const stepCount = duration / stepTime;
  const increment = targetScore / stepCount;

  const timer = setInterval(() => {
    current += increment;
    if (current >= targetScore) {
      clearInterval(timer);
      gaugeNumber.textContent = targetScore.toString();
    } else {
      gaugeNumber.textContent = Math.round(current).toString();
    }
  }, stepTime);
}

/**
 * Render a single extracted field safely using textContent
 */
function renderField(element, value) {
  if (value && typeof value === "string" && value.trim() && value.toLowerCase() !== "null") {
    element.textContent = value.trim();
    element.classList.remove("null-value");
  } else {
    element.textContent = "Not visible";
    element.classList.add("null-value");
  }
}

/**
 * Render red flags with staggered animation using textContent (preventing XSS)
 */
function renderRedFlags(flags) {
  // Clear existing items safely
  while (redFlagsList.firstChild) {
    redFlagsList.removeChild(redFlagsList.firstChild);
  }

  if (Array.isArray(flags) && flags.length > 0) {
    flags.forEach((flag, index) => {
      const li = document.createElement("li");
      li.className = "red-flag-item";
      li.style.animationDelay = `${index * 120}ms`;

      // Red flag warning icon created safely via DOM
      const svgIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svgIcon.setAttribute("class", "red-flag-icon");
      svgIcon.setAttribute("viewBox", "0 0 24 24");
      svgIcon.setAttribute("fill", "none");
      svgIcon.setAttribute("stroke", "currentColor");
      svgIcon.setAttribute("stroke-width", "2");
      svgIcon.setAttribute("stroke-linecap", "round");
      svgIcon.setAttribute("stroke-linejoin", "round");

      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z");
      const line1 = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line1.setAttribute("x1", "12");
      line1.setAttribute("y1", "9");
      line1.setAttribute("x2", "12");
      line1.setAttribute("y2", "13");
      const line2 = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line2.setAttribute("x1", "12");
      line2.setAttribute("y1", "17");
      line2.setAttribute("x2", "12.01");
      line2.setAttribute("y2", "17");

      svgIcon.appendChild(path);
      svgIcon.appendChild(line1);
      svgIcon.appendChild(line2);

      const spanText = document.createElement("span");
      spanText.textContent = String(flag); // Safely sets textContent

      li.appendChild(svgIcon);
      li.appendChild(spanText);
      redFlagsList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.className = "no-red-flags-note";
    li.textContent = "No specific red flags flagged in this image.";
    redFlagsList.appendChild(li);
  }
}

/**
 * Reset interface for another scan
 */
function resetApp() {
  fileInput.value = "";
  previewImage.src = "";
  uploadCard.classList.remove("hidden");
  previewCard.classList.add("hidden");
  resultsSection.classList.add("hidden");
  scanLaser.classList.add("hidden");
  wakeupNotice.classList.add("hidden");
  hideError();
  if (typeof window.scrollTo === "function") {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}

/**
 * Display error banner safely with textContent
 */
function showError(message) {
  errorText.textContent = message;
  errorBanner.classList.remove("hidden");
  if (typeof errorBanner.scrollIntoView === "function") {
    errorBanner.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

/**
 * Hide error banner
 */
function hideError() {
  errorBanner.classList.add("hidden");
  errorText.textContent = "";
}

