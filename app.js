"use strict";

// === SECURITY CONFIG ===
const STORAGE_KEY = "booking-system:v1:reservations";
const TOKEN_HASH_KEY = "booking-system:v1:adminTokenHash";
const TOKEN_SALT_KEY = "booking-system:v1:tokenSalt";
const ADMIN_SESSION_KEY = "booking-system:v1:adminSessionUntil";
const AUDIT_LOG_KEY = "booking-system:v1:auditLog";
const ADMIN_SESSION_MINUTES = 15;
const PBKDF2_ITERATIONS = 100000; // NIST recommended min
const RATE_LIMIT_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000; // 5 min

const INVENTORY = [
    { id: "camera-a", name: "Camera A" },
    { id: "camera-b", name: "Camera B" },
    { id: "lights", name: "Lighting Kit" },
    { id: "mics", name: "Wireless Mic Set" },
    { id: "tripods", name: "Tripods" },
    { id: "projector", name: "Projector" }
];

const TIME_SLOTS = [
    "08:00 - 10:00",
    "10:30 - 12:30",
    "13:00 - 15:00",
    "15:30 - 17:30",
    "18:00 - 20:00"
];

const els = {
    form: document.querySelector("#booking-form"),
    team: document.querySelector("#team-name"),
    date: document.querySelector("#booking-date"),
    slot: document.querySelector("#time-slot"),
    inventoryWrap: document.querySelector("#inventory-options"),
    message: document.querySelector("#message"),
    reservationCount: document.querySelector("#reservation-count"),
    reservationsList: document.querySelector("#reservations-list"),
    tokenForm: document.querySelector("#token-form"),
    tokenInput: document.querySelector("#token-input"),
    setTokenBtn: document.querySelector("#set-token"),
    unlockBtn: document.querySelector("#unlock-admin"),
    lockBtn: document.querySelector("#lock-admin"),
    clearBtn: document.querySelector("#clear-reservations"),
    viewAuditBtn: document.querySelector("#view-audit-log"),
    adminState: document.querySelector("#admin-state"),
    auditModal: document.querySelector("#audit-modal"),
    closeAuditBtn: document.querySelector("#close-audit-modal"),
    auditLogList: document.querySelector("#audit-log-list")
};

function nowMs() {
    return Date.now();
}

function sanitizeName(value) {
    return value.replace(/\s+/g, " ").trim().slice(0, 64);
}

function parseJson(value, fallback) {
    try {
        return JSON.parse(value);
    } catch {
        return fallback;
    }
}

function getReservations() {
    const raw = localStorage.getItem(STORAGE_KEY);
    const list = parseJson(raw, []);
    if (!Array.isArray(list)) {
        return [];
    }

    return list.filter(item => {
        return (
            item &&
            typeof item.id === "string" &&
            typeof item.team === "string" &&
            typeof item.date === "string" &&
            typeof item.slot === "string" &&
            Array.isArray(item.inventory)
        );
    });
}

function saveReservations(reservations) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(reservations));
}

function getAdminSessionUntil() {
    const raw = sessionStorage.getItem(ADMIN_SESSION_KEY);
    const until = Number(raw);
    return Number.isFinite(until) ? until : 0;
}

function isAdminUnlocked() {
    return getAdminSessionUntil() > nowMs();
}

function setAdminSession(minutes) {
    const until = nowMs() + minutes * 60 * 1000;
    sessionStorage.setItem(ADMIN_SESSION_KEY, String(until));
}

function clearAdminSession() {
    sessionStorage.removeItem(ADMIN_SESSION_KEY);
}

function arrayToHex(arr) {
    return Array.from(new Uint8Array(arr))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function hexToArray(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

// PBKDF2 key derivation (much stronger than simple SHA256)
async function deriveTokenKeyPBKDF2(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuf = encoder.encode(password);
    const saltBuf = hexToArray(salt);
    
    const baseKey = await crypto.subtle.importKey("raw", passwordBuf, "PBKDF2", false, [
        "deriveBits"
    ]);
    
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: saltBuf,
            iterations: PBKDF2_ITERATIONS
        },
        baseKey,
        256
    );
    
    return arrayToHex(derivedBits);
}

// Generate random salt
function generateSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return arrayToHex(bytes);
}

// AES-GCM encryption for sensitive data
async function encryptData(data, key) {
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const keyBuf = await crypto.subtle.importKey("raw", hexToArray(key), "AES-GCM", false, [
        "encrypt"
    ]);
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        keyBuf,
        encoder.encode(data)
    );
    return arrayToHex(iv) + ":" + arrayToHex(encrypted);
}

// AES-GCM decryption
async function decryptData(encryptedData, key) {
    const [ivHex, cipherHex] = encryptedData.split(":");
    if (!ivHex || !cipherHex) return null;
    
    const keyBuf = await crypto.subtle.importKey("raw", hexToArray(key), "AES-GCM", false, [
        "decrypt"
    ]);
    
    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: hexToArray(ivHex) },
            keyBuf,
            hexToArray(cipherHex)
        );
        return new TextDecoder().decode(decrypted);
    } catch {
        return null;
    }
}

// HMAC integrity check
async function computeHmac(data, key) {
    const encoder = new TextEncoder();
    const keyBuf = await crypto.subtle.importKey("raw", hexToArray(key), "HMAC", false, [
        "sign"
    ]);
    const signature = await crypto.subtle.sign("HMAC", keyBuf, encoder.encode(data));
    return arrayToHex(signature);
}

function getStoredTokenHash() {
    return localStorage.getItem(TOKEN_HASH_KEY) || "";
}

function getTokenSalt() {
    return localStorage.getItem(TOKEN_SALT_KEY) || "";
}

// Rate limiting: track failed attempts
function getRateLimitData() {
    const raw = sessionStorage.getItem("booking-system:v1:rateLimitAttempts");
    const data = parseJson(raw, { attempts: 0, firstAttemptAt: 0 });
    return data;
}

function updateRateLimitData(now) {
    const data = getRateLimitData();
    const timeSinceFirst = now - data.firstAttemptAt;
    
    if (timeSinceFirst > RATE_LIMIT_WINDOW_MS) {
        // Reset
        data.attempts = 1;
        data.firstAttemptAt = now;
    } else {
        data.attempts++;
    }
    
    sessionStorage.setItem("booking-system:v1:rateLimitAttempts", JSON.stringify(data));
    return data;
}

function isRateLimited() {
    const data = getRateLimitData();
    const now = nowMs();
    const timeSinceFirst = now - data.firstAttemptAt;
    
    if (timeSinceFirst > RATE_LIMIT_WINDOW_MS) {
        return false;
    }
    
    return data.attempts >= RATE_LIMIT_ATTEMPTS;
}

// Immutable audit log
function appendAuditLog(action, details = {}) {
    const log = parseJson(localStorage.getItem(AUDIT_LOG_KEY), []);
    if (!Array.isArray(log)) return;
    
    log.push({
        timestamp: new Date().toISOString(),
        action,
        details,
        userAgent: navigator.userAgent.slice(0, 128)
    });
    
    // Keep only last 1000 entries
    if (log.length > 1000) {
        log.shift();
    }
    
    localStorage.setItem(AUDIT_LOG_KEY, JSON.stringify(log));
}

function getAuditLog() {
    const log = parseJson(localStorage.getItem(AUDIT_LOG_KEY), []);
    return Array.isArray(log) ? log : [];
}

function setStatus(text, type = "info") {
    els.message.textContent = text;
    els.message.dataset.type = type;
}

function selectedInventoryIds() {
    const checked = els.inventoryWrap.querySelectorAll("input[type='checkbox']:checked");
    return Array.from(checked).map(input => input.value);
}

function inventoryNameById(id) {
    const item = INVENTORY.find(inv => inv.id === id);
    return item ? item.name : id;
}

function conflictsWithExisting(reservations, date, slot, inventoryIds) {
    const unavailable = new Set();

    for (const reservation of reservations) {
        if (reservation.date !== date || reservation.slot !== slot) {
            continue;
        }

        for (const id of reservation.inventory) {
            unavailable.add(id);
        }
    }

    return inventoryIds.filter(id => unavailable.has(id));
}

function updateAvailableInventoryHints() {
    const reservations = getReservations();
    const date = els.date.value;
    const slot = els.slot.value;

    const unavailableSet = new Set();
    for (const reservation of reservations) {
        if (reservation.date === date && reservation.slot === slot) {
            reservation.inventory.forEach(id => unavailableSet.add(id));
        }
    }

    const blocks = els.inventoryWrap.querySelectorAll("label");
    blocks.forEach(block => {
        const checkbox = block.querySelector("input[type='checkbox']");
        const isTaken = unavailableSet.has(checkbox.value);
        checkbox.disabled = isTaken;
        if (isTaken) {
            checkbox.checked = false;
        }
        block.classList.toggle("is-unavailable", isTaken);
    });
}

function updateAdminUi() {
    const hasToken = Boolean(getStoredTokenHash());
    const unlocked = hasToken && isAdminUnlocked();

    els.clearBtn.disabled = !unlocked;
    els.lockBtn.disabled = !unlocked;
    els.unlockBtn.disabled = !hasToken;
    els.viewAuditBtn.disabled = !unlocked;

    if (!hasToken) {
        els.adminState.textContent = "No admin token set";
    } else if (unlocked) {
        const secondsLeft = Math.max(0, Math.floor((getAdminSessionUntil() - nowMs()) / 1000));
        els.adminState.textContent = `Admin unlocked (${secondsLeft}s left)`;
    } else {
        els.adminState.textContent = "Admin locked";
    }
}

function buildInventoryOptions() {
    els.inventoryWrap.innerHTML = "";

    for (const item of INVENTORY) {
        const label = document.createElement("label");
        label.className = "inventory-chip";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.value = item.id;

        const text = document.createElement("span");
        text.textContent = item.name;

        label.append(checkbox, text);
        els.inventoryWrap.appendChild(label);
    }
}

function buildTimeSlots() {
    els.slot.innerHTML = "";

    for (const slot of TIME_SLOTS) {
        const option = document.createElement("option");
        option.value = slot;
        option.textContent = slot;
        els.slot.appendChild(option);
    }
}

function renderReservations() {
    const reservations = getReservations();
    reservations.sort((a, b) => {
        const first = `${a.date} ${a.slot}`;
        const second = `${b.date} ${b.slot}`;
        return first.localeCompare(second);
    });

    els.reservationCount.textContent = String(reservations.length);
    els.reservationsList.innerHTML = "";

    if (reservations.length === 0) {
        const empty = document.createElement("p");
        empty.className = "empty-state";
        empty.textContent = "No reservations yet.";
        els.reservationsList.appendChild(empty);
        return;
    }

    for (const reservation of reservations) {
        const row = document.createElement("article");
        row.className = "reservation-item";

        const title = document.createElement("h3");
        title.textContent = `${reservation.team} • ${reservation.date}`;

        const meta = document.createElement("p");
        meta.textContent = `${reservation.slot} | ${reservation.inventory
            .map(inventoryNameById)
            .join(", ")}`;

        row.append(title, meta);

        if (isAdminUnlocked()) {
            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.className = "danger small";
            removeBtn.textContent = "Delete";
            removeBtn.addEventListener("click", () => {
                const list = getReservations();
                const filtered = list.filter(item => item.id !== reservation.id);
                saveReservations(filtered);
                appendAuditLog("reservation_deleted", { deletedId: reservation.id, team: reservation.team });
                renderReservations();
                updateAvailableInventoryHints();
                setStatus("Reservation deleted.", "success");
            });
            row.appendChild(removeBtn);
        }

        els.reservationsList.appendChild(row);
    }
}

function seedDateDefault() {
    const today = new Date();
    const yyyy = today.getFullYear();
    const mm = String(today.getMonth() + 1).padStart(2, "0");
    const dd = String(today.getDate()).padStart(2, "0");
    els.date.value = `${yyyy}-${mm}-${dd}`;
    els.date.min = els.date.value;
}

async function handleTokenForm(event) {
    event.preventDefault();

    const token = els.tokenInput.value.trim();
    const now = nowMs();
    
    if (isRateLimited()) {
        setStatus("Too many attempts. Try again later.", "error");
        appendAuditLog("token_attempt_blocked_rate_limit", { rateLimited: true });
        return;
    }

    if (token.length < 12) {
        setStatus("Token must be at least 12 characters.", "error");
        updateRateLimitData(now);
        appendAuditLog("token_attempt_invalid_length", { provided: token.length });
        return;
    }

    if (event.submitter === els.setTokenBtn) {
        const salt = generateSalt();
        const hash = await deriveTokenKeyPBKDF2(token, salt);
        localStorage.setItem(TOKEN_HASH_KEY, hash);
        localStorage.setItem(TOKEN_SALT_KEY, salt);
        setAdminSession(ADMIN_SESSION_MINUTES);
        els.tokenInput.value = "";
        updateAdminUi();
        renderReservations();
        setStatus("Admin token saved securely (PBKDF2+salt) and unlocked.", "success");
        appendAuditLog("token_set", { timestamp: new Date().toISOString() });
        return;
    }

    if (event.submitter === els.unlockBtn) {
        const salt = getTokenSalt();
        const storedHash = getStoredTokenHash();
        
        if (!storedHash || !salt) {
            setStatus("Set a token first.", "error");
            updateRateLimitData(now);
            appendAuditLog("token_unlock_no_token_set");
            return;
        }

        const providedHash = await deriveTokenKeyPBKDF2(token, salt);
        if (providedHash !== storedHash) {
            setStatus("Invalid token.", "error");
            updateRateLimitData(now);
            appendAuditLog("token_unlock_failed_mismatch", {});
            return;
        }

        getRateLimitData().attempts = 0; // Reset on success
        setAdminSession(ADMIN_SESSION_MINUTES);
        els.tokenInput.value = "";
        updateAdminUi();
        renderReservations();
        setStatus("Admin unlocked.", "success");
        appendAuditLog("token_unlock_success", {});
    }
}

function handleCreateBooking(event) {
    event.preventDefault();

    const team = sanitizeName(els.team.value);
    const date = els.date.value;
    const slot = els.slot.value;
    const inventory = selectedInventoryIds();

    if (!team) {
        setStatus("Please enter a valid team name.", "error");
        return;
    }

    if (!date || !slot) {
        setStatus("Please pick a date and time slot.", "error");
        return;
    }

    if (inventory.length === 0) {
        setStatus("Select at least one inventory item.", "error");
        return;
    }

    const reservations = getReservations();
    const conflicts = conflictsWithExisting(reservations, date, slot, inventory);

    if (conflicts.length > 0) {
        setStatus(
            `Unavailable at that time: ${conflicts.map(inventoryNameById).join(", ")}`,
            "error"
        );
        return;
    }

    const reservation = {
        id: crypto.randomUUID(),
        team,
        date,
        slot,
        inventory,
        createdAt: new Date().toISOString()
    };

    reservations.push(reservation);
    saveReservations(reservations);
    appendAuditLog("reservation_created", { reservationId: reservation.id, team, date, slot });
    
    els.form.reset();
    seedDateDefault();
    buildTimeSlots();
    updateAvailableInventoryHints();
    renderReservations();
    setStatus("Reservation created.", "success");
}

function clearReservations() {
    if (!isAdminUnlocked()) {
        setStatus("Admin unlock required.", "error");
        return;
    }

    const approved = window.confirm("Delete all reservations?");
    if (!approved) {
        appendAuditLog("clear_reservations_cancelled", {});
        return;
    }

    const countBefore = getReservations().length;
    saveReservations([]);
    appendAuditLog("all_reservations_cleared", { countCleared: countBefore });
    renderReservations();
    updateAvailableInventoryHints();
    setStatus("All reservations cleared.", "success");
}

function showAuditLog() {
    const log = getAuditLog();
    els.auditLogList.innerHTML = "";

    if (log.length === 0) {
        const empty = document.createElement("p");
        empty.className = "empty-state";
        empty.style.padding = "1rem";
        empty.textContent = "No audit log entries.";
        els.auditLogList.appendChild(empty);
    } else {
        // Show in reverse (newest first)
        for (let i = log.length - 1; i >= 0; i--) {
            const entry = log[i];
            const div = document.createElement("div");
            div.className = "audit-entry";

            const time = document.createElement("span");
            time.className = "audit-entry-time";
            time.textContent = new Date(entry.timestamp).toLocaleString();

            const action = document.createElement("div");
            action.className = "audit-entry-action";
            action.textContent = entry.action;

            const details = document.createElement("div");
            details.className = "audit-entry-details";
            details.textContent = JSON.stringify(entry.details, null, 2).slice(0, 200);

            div.append(time, action, details);
            els.auditLogList.appendChild(div);
        }
    }

    els.auditModal.classList.remove("hidden");
}

function closeAuditLog() {
    els.auditModal.classList.add("hidden");
}

function init() {
    buildInventoryOptions();
    buildTimeSlots();
    seedDateDefault();
    renderReservations();
    updateAvailableInventoryHints();
    updateAdminUi();

    els.form.addEventListener("submit", handleCreateBooking);
    els.date.addEventListener("change", updateAvailableInventoryHints);
    els.slot.addEventListener("change", updateAvailableInventoryHints);
    els.tokenForm.addEventListener("submit", handleTokenForm);
    els.lockBtn.addEventListener("click", () => {
        clearAdminSession();
        updateAdminUi();
        renderReservations();
        setStatus("Admin locked.", "info");
    });
    els.clearBtn.addEventListener("click", clearReservations);
    els.viewAuditBtn.addEventListener("click", showAuditLog);
    els.closeAuditBtn.addEventListener("click", closeAuditLog);

    // Close modal on outside click
    els.auditModal.addEventListener("click", (e) => {
        if (e.target === els.auditModal) {
            closeAuditLog();
        }
    });

    // Keep the admin countdown state fresh while unlocked.
    window.setInterval(() => {
        const currentlyUnlocked = isAdminUnlocked();
        updateAdminUi();
        if (!currentlyUnlocked) {
            renderReservations();
        }
    }, 1000);
}

init();