const fileInput = document.querySelector("#file-input");
const dropzone = document.querySelector("#dropzone");
const fileList = document.querySelector("#file-list");
const expenseList = document.querySelector("#expense-list");
const emptyState = document.querySelector("#empty-state");
const expenseEmpty = document.querySelector("#expense-empty");
const feedback = document.querySelector("#upload-feedback");
const searchInput = document.querySelector("#search-input");
const documentDialog = document.querySelector("#document-dialog");
const transactionForm = document.querySelector("#transaction-form");
const transactionFeedback = document.querySelector("#transaction-feedback");
const bankFeedback = document.querySelector("#bank-feedback");
const authScreen = document.querySelector("#auth-screen");
const appShell = document.querySelector("#app-shell");
const authFeedback = document.querySelector("#auth-feedback");
const maxUploadSize = 25 * 1024 * 1024;
let files = [];
let csrfToken = "";
let activeFile = null;
let categorySpending = [];

function localDateString(value = new Date()) {
  const year = value.getFullYear();
  const month = String(value.getMonth() + 1).padStart(2, "0");
  const day = String(value.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

const documentTypeLabels = {
  factura: "Factura",
  recibo: "Recibo",
  contrato: "Contrato",
  estado_cuenta: "Estado de cuenta",
  otro: "Otro documento",
};

const expenseCategoryLabels = {
  alimentacion: "Alimentación",
  transporte: "Transporte",
  servicios: "Servicios",
  salud: "Salud",
  compras: "Compras",
  vivienda: "Vivienda",
  educacion: "Educación",
  otros: "Otros",
  renta: "Renta",
  marketing: "Marketing",
  administracion: "Administración",
  impuestos: "Impuestos",
  seguros: "Seguros",
  servicios_profesionales: "Servicios profesionales",
  comisiones_bancarias: "Comisiones bancarias",
  suministros_oficina: "Suministros de oficina",
};

const costTypeLabels = {
  materia_prima: "Materia prima",
  mano_obra_directa: "Mano de obra directa",
  adquisicion: "Costo de adquisición",
  otros: "Otros costos directos",
};

function categoryChoices(type) {
  return type === "costo"
    ? Object.entries(costTypeLabels)
    : Object.entries(expenseCategoryLabels);
}

function populateCategorySelect(select, type, selected = select.value) {
  const choices = categoryChoices(type);
  select.replaceChildren(...choices.map(([value, label]) => new Option(label, value)));
  if (choices.some(([value]) => value === selected)) select.value = selected;
}

function categoryLabel(type, category) {
  return (type === "costo" ? costTypeLabels : expenseCategoryLabels)[category] || category;
}

async function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
  return fetch(url, { ...options, headers });
}

function showAuthFeedback(message, isError = false) {
  authFeedback.textContent = message;
  authFeedback.classList.toggle("error", isError);
  authFeedback.hidden = !message;
}

function showLogin(status, message = "") {
  appShell.hidden = true;
  authScreen.hidden = false;
  csrfToken = status.csrf_token || csrfToken;
  const hasProvider = status.providers.length > 0;
  document.querySelectorAll("[data-provider]").forEach((link) => {
    link.hidden = !status.providers.includes(link.dataset.provider);
  });
  document.querySelector(".auth-divider").hidden = !hasProvider;
  document.querySelector(".oauth-buttons").hidden = !hasProvider;
  document.querySelector(".passkey-login").hidden =
    !window.isSecureContext || !window.PublicKeyCredential;
  showAuthFeedback(message, Boolean(message));
}

function showApp(user, hasPasskey) {
  authScreen.hidden = true;
  appShell.hidden = false;
  document.querySelector("#profile-name").textContent = user.email;
  document.querySelector("#passkey-enable-button").hidden =
    hasPasskey || !window.isSecureContext || !window.PublicKeyCredential;
  if (!document.querySelector("#transaction-date").value) {
    document.querySelector("#transaction-date").value = localDateString();
  }
  loadTransactions();
  loadRecurringTransactions();
  loadFiles();
}

async function returnToLogin(message) {
  files = [];
  fileList.replaceChildren();
  updateSummary();
  const response = await fetch("/api/auth/status");
  const status = await responseError(response, "No se pudo comprobar tu sesión.");
  showLogin(status, message);
}

async function responseError(response, fallback) {
  let result;
  try {
    result = await response.json();
  } catch {
    const contentType = response.headers.get("content-type") || "";
    const detail = response.status === 404
      ? "La ruta no existe en el servidor. Reinicia Flask para cargar las rutas más recientes."
      : contentType.includes("text/html")
        ? `El servidor devolvió una página HTML en lugar de JSON (HTTP ${response.status}). Comprueba la URL de Flask y reinicia la aplicación.`
        : `El servidor respondió con contenido no válido (HTTP ${response.status}).`;
    throw new Error(`${fallback} ${detail}`);
  }
  if (!result || typeof result !== "object") {
    throw new Error(`${fallback} El servidor devolvió una respuesta inesperada.`);
  }
  if (!response.ok) throw new Error(result.error || `${fallback} (HTTP ${response.status}).`);
  return result;
}

function setAuthMode(mode) {
  const isLogin = mode === "login";
  const loginTab = document.querySelector("#login-tab");
  const registerTab = document.querySelector("#register-tab");
  loginTab.classList.toggle("active", isLogin);
  registerTab.classList.toggle("active", !isLogin);
  loginTab.setAttribute("aria-selected", String(isLogin));
  registerTab.setAttribute("aria-selected", String(!isLogin));
  document.querySelector("#login-form").hidden = !isLogin;
  document.querySelector("#register-form").hidden = isLogin;
  showAuthFeedback("");
}

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

function encodeBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function credentialPayload(credential) {
  const response = {
    clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
  };
  if (credential.response.attestationObject) {
    response.attestationObject = encodeBase64Url(credential.response.attestationObject);
    if (credential.response.getTransports) response.transports = credential.response.getTransports();
  } else {
    response.authenticatorData = encodeBase64Url(credential.response.authenticatorData);
    response.signature = encodeBase64Url(credential.response.signature);
    if (credential.response.userHandle) response.userHandle = encodeBase64Url(credential.response.userHandle);
  }
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment,
  };
}

async function authenticateWithPasskey() {
  if (!window.isSecureContext || !window.PublicKeyCredential) {
    showAuthFeedback("Las passkeys requieren un navegador compatible y una conexión HTTPS.", true);
    return;
  }
  const email = document.querySelector("#passkey-email").value.trim();
  try {
    const optionResponse = await apiFetch("/api/auth/passkeys/login/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const options = await responseError(optionResponse, "No se pudo iniciar la autenticación biométrica.");
    options.challenge = decodeBase64Url(options.challenge);
    options.allowCredentials = options.allowCredentials.map((item) => ({
      ...item,
      id: decodeBase64Url(item.id),
    }));
    const credential = await navigator.credentials.get({ publicKey: options });
    if (!credential) throw new Error("No se completó la autenticación biométrica.");
    const verifyResponse = await apiFetch("/api/auth/passkeys/login/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentialPayload(credential)),
    });
    const result = await responseError(verifyResponse, "No se pudo verificar la passkey.");
    csrfToken = result.csrf_token;
    showApp(result.user, result.has_passkey);
  } catch (error) {
    showAuthFeedback(error.message, true);
  }
}

async function initializeAuth() {
  try {
    const response = await fetch("/api/auth/status");
    const status = await responseError(response, "No se pudo comprobar tu sesión.");
    csrfToken = status.csrf_token;
    if (status.authenticated) showApp(status.user, status.has_passkey);
    else showLogin(status);
  } catch (error) {
    showLogin({ providers: [] }, error.message);
  }
}

const formatSize = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const formatDate = (value) => new Intl.DateTimeFormat("es", {
  day: "2-digit",
  month: "short",
  year: "numeric",
}).format(new Date(value));

function formatMoney(value) {
  if (value === null || value === undefined || value === "") return "Monto pendiente";
  return Number(value).toLocaleString("es", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function formatCopCents(value) {
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency: "COP",
    maximumFractionDigits: 2,
  }).format(value / 100);
}

function formatFinancialPesos(value) {
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency: "COP",
    maximumFractionDigits: 0,
  }).format(value);
}

function updateFinancialCheck() {
  const income = document.querySelector("#financial-income").valueAsNumber;
  const fixed = document.querySelector("#financial-fixed").valueAsNumber || 0;
  const variable = document.querySelector("#financial-variable").valueAsNumber || 0;
  const debt = document.querySelector("#financial-debt").valueAsNumber || 0;
  const totalExpenses = fixed + variable + debt;
  const totalElement = document.querySelector("#financial-total");
  const availableElement = document.querySelector("#financial-available");
  const feedbackElement = document.querySelector("#financial-check-feedback");
  const balanceElement = document.querySelector(".financial-balance");

  totalElement.textContent = formatFinancialPesos(totalExpenses);
  balanceElement.classList.remove("negative");
  if (!Number.isFinite(income)) {
    availableElement.textContent = "Ingresa tu ingreso";
    feedbackElement.textContent = "El cálculo es orientativo y no guarda estos valores. Registra tus movimientos para llevar un seguimiento.";
    return;
  }

  const available = income - totalExpenses;
  availableElement.textContent = formatFinancialPesos(available);
  if (available < 0) {
    balanceElement.classList.add("negative");
    feedbackElement.textContent = "Tus egresos superan el ingreso registrado. Revisa primero gastos no esenciales y contacta a tus acreedores para consultar opciones formales antes de asumir otra deuda.";
  } else if (available === 0) {
    feedbackElement.textContent = "Tu ingreso está comprometido por completo. Revisa el presupuesto y procura separar un monto para imprevistos, aunque sea pequeño.";
  } else {
    feedbackElement.textContent = `Te quedan ${formatFinancialPesos(available)} estimados. Puedes asignarlos a ahorro, metas u obligaciones pendientes antes de aumentar tus gastos.`;
  }
}

function showTransactionFeedback(target, message, isError = false) {
  target.textContent = message;
  target.classList.toggle("error", isError);
  target.hidden = !message;
}

function appendTransactionRow(list, transaction, isCost) {
  const row = document.createElement("tr");
  const values = isCost
    ? [
      formatDate(`${transaction.date}T00:00:00`),
      [transaction.description, transaction.vendor].filter(Boolean).join(" · "),
      costTypeLabels[transaction.cost_type] || costTypeLabels.otros,
      formatCopCents(transaction.amount_cents),
    ]
    : [
      formatDate(`${transaction.date}T00:00:00`),
      [transaction.description, transaction.vendor].filter(Boolean).join(" · "),
      expenseCategoryLabels[transaction.category] || expenseCategoryLabels.otros,
      transaction.nature === "fijo" ? "Fijo" : "Variable",
      formatCopCents(transaction.amount_cents),
    ];
  for (const value of values) {
    const cell = document.createElement("td");
    cell.textContent = value || "—";
    row.append(cell);
  }
  const actionsCell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "row-actions";
  if (transaction.file_id && transaction.file_name) {
    const fileLink = document.createElement("a");
    fileLink.className = "row-action";
    fileLink.href = `/api/files/${encodeURIComponent(transaction.file_id)}/download`;
    fileLink.textContent = "Comprobante";
    actions.append(fileLink);
  }
  const remove = document.createElement("button");
  remove.className = "row-action delete";
  remove.type = "button";
  remove.textContent = "Eliminar";
  remove.addEventListener("click", () => deleteTransaction(transaction));
  actions.append(remove);
  actionsCell.append(actions);
  row.append(actionsCell);
  list.append(row);
}

function renderTransactions(result) {
  categorySpending = result.category_spending || [];
  const expenses = result.transactions.filter((transaction) => transaction.type === "gasto");
  const costs = result.transactions.filter((transaction) => transaction.type === "costo");
  const expenseList = document.querySelector("#transaction-expense-list");
  const costList = document.querySelector("#transaction-cost-list");
  expenseList.replaceChildren();
  costList.replaceChildren();
  expenses.forEach((transaction) => appendTransactionRow(expenseList, transaction, false));
  costs.forEach((transaction) => appendTransactionRow(costList, transaction, true));
  document.querySelector("#expense-ledger-empty").hidden = expenses.length > 0;
  document.querySelector("#cost-ledger-empty").hidden = costs.length > 0;

  const summary = result.summary;
  document.querySelector("#monthly-expenses").textContent = formatCopCents(summary.expenses_cents);
  document.querySelector("#fixed-expenses").textContent = formatCopCents(summary.fixed_expenses_cents);
  document.querySelector("#variable-expenses").textContent = formatCopCents(summary.variable_expenses_cents);
  document.querySelector("#monthly-costs").textContent = formatCopCents(summary.costs_cents);
  document.querySelector("#expense-total").textContent = formatCopCents(summary.expenses_cents);
  document.querySelector("#cost-total").textContent = formatCopCents(summary.costs_cents);
  document.querySelector("#bank-status").textContent = result.bank_sync.message;

  const fileSelect = document.querySelector("#transaction-file");
  const selectedFile = fileSelect.value;
  fileSelect.replaceChildren(new Option("Sin comprobante", ""));
  files.forEach((file) => fileSelect.add(new Option(file.name, file.id)));
  if ([...fileSelect.options].some((option) => option.value === selectedFile)) {
    fileSelect.value = selectedFile;
  }
  const recurring = document.querySelector("#make-recurring").checked;
  fileSelect.closest("div").hidden = recurring;
  updateScenarioProjection();
}

async function loadTransactions() {
  try {
    const response = await apiFetch("/api/transactions");
    if (response.status === 401) {
      await returnToLogin("Tu sesión expiró. Inicia sesión de nuevo.");
      return;
    }
    const result = await responseError(response, "No se pudieron cargar las transacciones.");
    renderTransactions(result);
    await loadBudgets();
  } catch (error) {
    showFeedback(error.message, true);
  }
}

function renderBudgetDashboard(result) {
  const budgetList = document.querySelector("#budget-list");
  budgetList.replaceChildren();
  const monthDate = new Date(`${result.month}-01T00:00:00`);
  document.querySelector("#budget-month").textContent = new Intl.DateTimeFormat("es-CO", {
    month: "long",
    year: "numeric",
  }).format(monthDate);
  document.querySelector("#budget-empty").hidden = result.budgets.length > 0;
  for (const budget of result.budgets) {
    const row = document.createElement("tr");
    const categoryCell = document.createElement("td");
    categoryCell.textContent = `${categoryLabel(budget.type, budget.category)} · ${budget.type === "gasto" ? "Gasto" : "Costo"}`;
    const amountCell = document.createElement("td");
    amountCell.textContent = `${formatCopCents(budget.spent_cents)} / ${formatCopCents(budget.limit_cents)}`;
    const progressCell = document.createElement("td");
    const progress = document.createElement("progress");
    progress.max = 100;
    progress.value = Math.min(budget.progress_percent, 100);
    progress.setAttribute("aria-label", `Presupuesto usado: ${budget.progress_percent}%`);
    const percentage = document.createElement("span");
    percentage.className = `budget-percentage ${budget.status}`;
    percentage.textContent = `${budget.progress_percent}% · ${
      budget.status === "exceeded" ? "Superado" : budget.status === "warning" ? "Alerta 80%" : "En rango"
    }`;
    progressCell.append(progress, percentage);
    const actionsCell = document.createElement("td");
    const remove = document.createElement("button");
    remove.className = "row-action delete";
    remove.type = "button";
    remove.textContent = "Eliminar";
    remove.setAttribute("aria-label", `Eliminar presupuesto de ${categoryLabel(budget.type, budget.category)}`);
    remove.addEventListener("click", () => deleteBudget(budget));
    actionsCell.append(remove);
    row.append(categoryCell, amountCell, progressCell, actionsCell);
    budgetList.append(row);
  }

  const alerts = document.querySelector("#budget-alerts");
  alerts.replaceChildren();
  alerts.hidden = result.alerts.length === 0;
  result.alerts.forEach((budget) => {
    const message = document.createElement("p");
    message.className = `budget-alert-item ${budget.status}`;
    const category = categoryLabel(budget.type, budget.category);
    message.textContent = budget.status === "exceeded"
      ? `Límite superado: ${category} lleva ${formatCopCents(budget.spent_cents)} de ${formatCopCents(budget.limit_cents)}.`
      : `Alerta: ${category} alcanzó el ${budget.progress_percent}% de su límite mensual (${formatCopCents(budget.spent_cents)} de ${formatCopCents(budget.limit_cents)}).`;
    alerts.append(message);
  });
}

async function loadBudgets() {
  try {
    const response = await apiFetch("/api/budgets");
    if (response.status === 401) return;
    const result = await responseError(response, "No se pudieron cargar los presupuestos.");
    renderBudgetDashboard(result);
  } catch (error) {
    showFeedback(error.message, true);
  }
}

async function deleteBudget(budget) {
  if (!window.confirm(`¿Eliminar el presupuesto mensual de ${categoryLabel(budget.type, budget.category)}?`)) return;
  try {
    const response = await apiFetch(`/api/budgets/${encodeURIComponent(budget.id)}`, { method: "DELETE" });
    const result = await responseError(response, "No se pudo eliminar el presupuesto.");
    renderBudgetDashboard(result);
    showTransactionFeedback(document.querySelector("#budget-feedback"), "Presupuesto eliminado.");
  } catch (error) {
    showTransactionFeedback(document.querySelector("#budget-feedback"), error.message, true);
  }
}

function updateScenarioProjection() {
  const type = document.querySelector("#scenario-type").value;
  const category = document.querySelector("#scenario-category").value;
  const baseCents = categorySpending.find(
    (item) => item.type === type && item.category === category,
  )?.spent_cents || 0;
  const reductionPercent = Number(document.querySelector("#scenario-reduction").value);
  const months = Number(document.querySelector("#scenario-months").value);
  const investment = Number(document.querySelector("#scenario-investment").value);
  const monthlyBenefit = Number(document.querySelector("#scenario-benefit").value);
  const validProjection = Number.isFinite(reductionPercent)
    && reductionPercent >= 0 && reductionPercent <= 100
    && Number.isInteger(months) && months >= 1 && months <= 60
    && Number.isFinite(investment) && investment >= 0 && investment <= 999999999999
    && Number.isFinite(monthlyBenefit) && monthlyBenefit >= 0 && monthlyBenefit <= 999999999999;
  const savingsCents = validProjection
    ? Math.round(baseCents * reductionPercent / 100) * months
    : 0;
  const benefitsCents = validProjection ? Math.round(monthlyBenefit * 100) * months : 0;
  const investmentCents = validProjection ? Math.round(investment * 100) : 0;
  document.querySelector("#scenario-baseline").textContent = formatCopCents(baseCents);
  document.querySelector("#scenario-savings").textContent = formatCopCents(savingsCents);
  document.querySelector("#scenario-benefits").textContent = formatCopCents(benefitsCents);
  document.querySelector("#scenario-investment-result").textContent = formatCopCents(investmentCents);
  const netImpact = savingsCents + benefitsCents - investmentCents;
  const netOutput = document.querySelector("#scenario-net");
  netOutput.textContent = `${netImpact < 0 ? "−" : "+"}${formatCopCents(Math.abs(netImpact))}`;
  netOutput.parentElement.classList.toggle("negative", netImpact < 0);
}

function renderRecurringTransactions(schedules) {
  const list = document.querySelector("#recurring-list");
  list.replaceChildren();
  document.querySelector("#recurring-empty").hidden = schedules.length > 0;
  for (const schedule of schedules) {
    const row = document.createElement("tr");
    const amount = formatCopCents(schedule.amount_cents);
    const frequency = `${schedule.frequency[0].toUpperCase()}${schedule.frequency.slice(1)}${schedule.interval > 1 ? ` · cada ${schedule.interval}` : ""}`;
    const values = [
      [schedule.description, schedule.vendor].filter(Boolean).join(" · "),
      schedule.type === "gasto" ? "Gasto" : "Costo",
      frequency,
      amount,
      formatDate(`${schedule.next_run_date}T00:00:00`),
    ];
    for (const value of values) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    const actionsCell = document.createElement("td");
    if (schedule.active) {
      const cancel = document.createElement("button");
      cancel.className = "row-action delete";
      cancel.type = "button";
      cancel.textContent = "Cancelar";
      cancel.addEventListener("click", () => cancelRecurringTransaction(schedule));
      actionsCell.append(cancel);
    } else {
      actionsCell.textContent = "Cancelada";
    }
    row.append(actionsCell);
    list.append(row);
  }
}

async function loadRecurringTransactions() {
  try {
    const response = await apiFetch("/api/recurring-transactions");
    if (response.status === 401) return;
    const result = await responseError(response, "No se pudieron cargar las transacciones programadas.");
    renderRecurringTransactions(result);
  } catch (error) {
    showFeedback(error.message, true);
  }
}

async function deleteTransaction(transaction) {
  if (!window.confirm(`¿Eliminar "${transaction.description}" por ${formatCopCents(transaction.amount_cents)}?`)) return;
  try {
    const response = await apiFetch(`/api/transactions/${encodeURIComponent(transaction.id)}`, { method: "DELETE" });
    await responseError(response, "No se pudo eliminar la transacción.");
    await Promise.all([loadTransactions(), loadFiles()]);
    showFeedback("Transacción eliminada.");
  } catch (error) {
    showFeedback(error.message, true);
  }
}

async function cancelRecurringTransaction(schedule) {
  if (!window.confirm(`¿Cancelar la recurrencia "${schedule.description}"? Las transacciones ya generadas se conservarán.`)) return;
  try {
    const response = await apiFetch(`/api/recurring-transactions/${encodeURIComponent(schedule.id)}`, { method: "DELETE" });
    await responseError(response, "No se pudo cancelar la recurrencia.");
    await loadRecurringTransactions();
    showTransactionFeedback(transactionFeedback, "Recurrencia cancelada.");
  } catch (error) {
    showTransactionFeedback(transactionFeedback, error.message, true);
  }
}

function updateSummary() {
  document.querySelector("#file-count").textContent = files.length;
  const used = files.reduce((total, file) => total + file.size, 0);
  document.querySelector("#storage-used").textContent = formatSize(used);
}

function renderFiles() {
  const query = searchInput.value.trim().toLocaleLowerCase("es");
  const visibleFiles = files.filter((file) => file.name.toLocaleLowerCase("es").includes(query));
  fileList.replaceChildren();
  emptyState.hidden = visibleFiles.length > 0;
  if (!visibleFiles.length && files.length && query) {
    emptyState.querySelector("strong").textContent = "No se encontraron archivos";
    emptyState.querySelector("span").textContent = "Prueba con otro nombre.";
  } else {
    emptyState.querySelector("strong").textContent = "Aún no hay documentos";
    emptyState.querySelector("span").textContent = "Sube tu primer archivo para empezar a organizar tus finanzas.";
  }

  for (const file of visibleFiles) {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const name = document.createElement("div");
    const icon = document.createElement("span");
    icon.className = `file-icon ${file.extension}`;
    icon.textContent = file.extension.slice(0, 3).toUpperCase();
    name.className = "file-name";
    name.append(icon, document.createTextNode(file.name));
    nameCell.append(name);

    const formatCell = document.createElement("td");
    const typeBadge = document.createElement("span");
    typeBadge.className = "format-badge document-type-badge";
    typeBadge.textContent = documentTypeLabels[file.document_type] || documentTypeLabels.otro;
    const formatBadge = document.createElement("span");
    formatBadge.className = "format-badge";
    formatBadge.textContent = file.extension.toUpperCase();
    formatCell.append(typeBadge, formatBadge);

    const expenseCell = document.createElement("td");
    if (file.expense) {
      const expenseSummary = document.createElement("div");
      expenseSummary.className = "expense-summary";
      const vendor = document.createElement("strong");
      vendor.textContent = file.expense.vendor || "Proveedor pendiente";
      const amount = document.createElement("span");
      amount.textContent = formatMoney(file.expense.amount);
      const category = document.createElement("small");
      category.textContent = expenseCategoryLabels[file.expense.category] || expenseCategoryLabels.otros;
      expenseSummary.append(vendor, amount, category);
      expenseCell.append(expenseSummary);
    } else {
      expenseCell.textContent = "Sin gasto vinculado";
      expenseCell.className = "muted-cell";
    }

    const dateCell = document.createElement("td");
    dateCell.textContent = formatDate(file.uploaded_at);
    const actionsCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const edit = document.createElement("button");
    edit.className = "row-action";
    edit.type = "button";
    edit.textContent = "Clasificar";
    edit.addEventListener("click", () => openDocumentEditor(file));
    const download = document.createElement("a");
    download.className = "row-action";
    download.href = `/api/files/${encodeURIComponent(file.id)}/download`;
    download.textContent = "Descargar";
    const remove = document.createElement("button");
    remove.className = "row-action delete";
    remove.type = "button";
    remove.textContent = "Eliminar";
    remove.addEventListener("click", () => deleteFile(file));
    actions.append(edit, download, remove);
    actionsCell.append(actions);
    row.append(nameCell, formatCell, expenseCell, dateCell, actionsCell);
    fileList.append(row);
  }
  updateSummary();
}

function renderExpenses(expenses) {
  expenseList.replaceChildren();
  expenseEmpty.hidden = expenses.length > 0;
  for (const expense of expenses) {
    const row = document.createElement("tr");
    for (const value of [
      expense.vendor || "Proveedor pendiente",
      expenseCategoryLabels[expense.category] || expenseCategoryLabels.otros,
      expense.date ? formatDate(`${expense.date}T00:00:00`) : "Fecha pendiente",
      formatMoney(expense.amount),
    ]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    const fileCell = document.createElement("td");
    const fileLink = document.createElement("a");
    fileLink.className = "row-action";
    fileLink.href = `/api/files/${encodeURIComponent(expense.file_id)}/download`;
    fileLink.textContent = expense.file_name;
    fileCell.append(fileLink);
    row.append(fileCell);
    expenseList.append(row);
  }
}

function openDocumentEditor(file) {
  activeFile = file;
  document.querySelector("#document-file-name").textContent = file.name;
  document.querySelector("#edit-document-type").value = file.document_type || "otro";
  const linked = Boolean(file.expense);
  document.querySelector("#link-expense").checked = linked;
  document.querySelector("#expense-fields").hidden = !linked;
  document.querySelector("#expense-vendor").value = file.expense?.vendor || "";
  document.querySelector("#expense-amount").value = file.expense?.amount ?? "";
  document.querySelector("#expense-date").value = file.expense?.date || "";
  document.querySelector("#expense-category").value = file.expense?.category || "otros";
  const statusMessage = {
    processed: "OCR procesado. Revisa los datos extraídos antes de guardar.",
    unavailable: "OCR pendiente: instala Tesseract OCR y los idiomas español e inglés. Puedes introducir los datos manualmente.",
    too_large: "La imagen supera el límite de procesamiento OCR; puedes completar los datos manualmente.",
    error: "No se pudo procesar la imagen con OCR. Revisa los datos o completa el gasto manualmente.",
  };
  const note = statusMessage[file.ocr_status] || "Puedes clasificar el documento y vincularlo a un gasto.";
  document.querySelector("#ocr-note").textContent = linked && file.ocr_status === "processed"
    ? `${note} Los datos sugeridos son editables.`
    : note;
  document.querySelector("#document-feedback").hidden = true;
  documentDialog.showModal();
}

async function loadExpenses() {
  try {
    const response = await apiFetch("/api/expenses");
    if (response.status === 401) {
      await returnToLogin("Tu sesión expiró. Inicia sesión de nuevo.");
      return;
    }
    const result = await responseError(response, "No se pudieron cargar los gastos vinculados.");
    renderExpenses(result);
  } catch (error) {
    showFeedback(error.message, true);
  }
}

function showFeedback(message, isError = false) {
  feedback.textContent = message;
  feedback.classList.toggle("error", isError);
  feedback.hidden = false;
}

async function loadFiles() {
  try {
    const response = await apiFetch("/api/files");
    if (response.status === 401) {
      await returnToLogin("Tu sesión expiró. Inicia sesión de nuevo.");
      return;
    }
    files = await responseError(response, "No se pudieron cargar los documentos.");
    renderFiles();
    await loadExpenses();
    await loadTransactions();
  } catch (error) {
    showFeedback(error.message, true);
  }
}

async function uploadFiles(selectedFiles) {
  const candidates = Array.from(selectedFiles);
  if (!candidates.length) return;
  const totalSize = candidates.reduce((total, file) => total + file.size, 0);
  if (totalSize > maxUploadSize) {
    showFeedback("El tamaño total de los archivos supera el límite de 25 MB.", true);
    return;
  }

  const data = new FormData();
  candidates.forEach((file) => data.append("files", file));
  data.append("document_type", document.querySelector("#upload-document-type").value);
  showFeedback("Subiendo archivos…");
  try {
    const response = await apiFetch("/api/files", { method: "POST", body: data });
    if (response.status === 401) {
      await returnToLogin("Tu sesión expiró. Inicia sesión de nuevo.");
      return;
    }
    const result = await responseError(response, "No se pudieron subir los archivos.");
    const messages = [];
    if (result.uploaded.length) messages.push(`${result.uploaded.length} archivo(s) subido(s) correctamente.`);
    const ocrUnavailable = result.uploaded.filter((file) => file.ocr_status === "unavailable").length;
    const ocrErrors = result.uploaded.filter((file) => ["error", "too_large"].includes(file.ocr_status)).length;
    if (ocrUnavailable) messages.push("OCR no configurado: las imágenes se guardaron y puedes completar sus datos manualmente.");
    if (ocrErrors) messages.push("No se pudo procesar una o más imágenes; revisa sus datos manualmente.");
    if (result.errors.length) messages.push(...result.errors.map((item) => `${item.name}: ${item.error}`));
    showFeedback(messages.join(" "), result.errors.length > 0 || ocrErrors > 0);
    fileInput.value = "";
    await loadFiles();
  } catch (error) {
    showFeedback(error.message, true);
  }
}

async function deleteFile(file) {
  if (!window.confirm(`¿Eliminar "${file.name}"?`)) return;
  try {
    const response = await apiFetch(`/api/files/${encodeURIComponent(file.id)}`, { method: "DELETE" });
    if (response.status === 401) {
      await returnToLogin("Tu sesión expiró. Inicia sesión de nuevo.");
      return;
    }
    await responseError(response, "No se pudo eliminar el archivo.");
    files = files.filter((item) => item.id !== file.id);
    renderFiles();
    await loadExpenses();
    await loadTransactions();
    showFeedback("Archivo eliminado.");
  } catch (error) {
    showFeedback(error.message, true);
  }
}

function openFilePicker() {
  fileInput.click();
}

document.querySelector("#login-tab").addEventListener("click", () => setAuthMode("login"));
document.querySelector("#register-tab").addEventListener("click", () => setAuthMode("register"));
document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showAuthFeedback("");
  const formElement = event.currentTarget;
  try {
    const form = new FormData(formElement);
    const response = await apiFetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
    });
    const result = await responseError(response, "No se pudo iniciar sesión.");
    csrfToken = result.csrf_token;
    formElement.reset();
    showApp(result.user, result.has_passkey);
  } catch (error) {
    showAuthFeedback(error.message, true);
  }
});
document.querySelector("#register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showAuthFeedback("");
  const formElement = event.currentTarget;
  try {
    const form = new FormData(formElement);
    const response = await apiFetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
    });
    const result = await responseError(response, "No se pudo crear la cuenta.");
    csrfToken = result.csrf_token;
    formElement.reset();
    showApp(result.user, result.has_passkey);
  } catch (error) {
    showAuthFeedback(error.message, true);
  }
});
document.querySelector("#passkey-login-button").addEventListener("click", authenticateWithPasskey);
document.querySelector("#financial-check-form").addEventListener("input", updateFinancialCheck);
document.querySelector("#financial-check-form").addEventListener("submit", (event) => event.preventDefault());
document.querySelector("#financial-check-form").addEventListener("change", updateFinancialCheck);
document.querySelectorAll("[data-copy-template]").forEach((button) => {
  button.addEventListener("click", async () => {
    const template = document.getElementById(button.dataset.copyTemplate);
    const feedbackTarget = document.querySelector(
      `[data-template-feedback="${button.dataset.copyTemplate}"]`,
    );
    if (!template || !feedbackTarget) {
      throw new Error("No se encontró la plantilla para copiar.");
    }

    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(template.value);
      } else {
        template.focus();
        template.select();
        if (!document.execCommand("copy")) {
          throw new Error("El navegador no permitió copiar el texto.");
        }
      }
      feedbackTarget.textContent = "Plantilla copiada. Completa los campos entre corchetes antes de presentarla.";
      feedbackTarget.classList.remove("error");
      feedbackTarget.hidden = false;
    } catch (error) {
      feedbackTarget.textContent = `No se pudo copiar la plantilla. Selecciona y copia el texto manualmente. ${error.message}`;
      feedbackTarget.classList.add("error");
      feedbackTarget.hidden = false;
    }
  });
});
document.querySelector("#budget-type").addEventListener("change", (event) => {
  populateCategorySelect(document.querySelector("#budget-category"), event.currentTarget.value);
});
document.querySelector("#scenario-type").addEventListener("change", (event) => {
  populateCategorySelect(document.querySelector("#scenario-category"), event.currentTarget.value);
  updateScenarioProjection();
});
document.querySelector("#scenario-category").addEventListener("change", updateScenarioProjection);
document.querySelector("#scenario-form").addEventListener("input", updateScenarioProjection);
document.querySelector("#scenario-form").addEventListener("submit", (event) => event.preventDefault());
document.querySelector("#budget-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const feedbackTarget = document.querySelector("#budget-feedback");
  showTransactionFeedback(feedbackTarget, "");
  const submitButton = form.querySelector(".budget-submit");
  submitButton.disabled = true;
  try {
    const response = await apiFetch("/api/budgets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: document.querySelector("#budget-type").value,
        category: document.querySelector("#budget-category").value,
        amount: document.querySelector("#budget-amount").value,
      }),
    });
    const result = await responseError(response, "No se pudo guardar el presupuesto.");
    renderBudgetDashboard(result);
    document.querySelector("#budget-amount").value = "";
    showTransactionFeedback(feedbackTarget, "Presupuesto mensual guardado.");
  } catch (error) {
    showTransactionFeedback(feedbackTarget, error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});
document.querySelector("#transaction-type").addEventListener("change", (event) => {
  const isCost = event.currentTarget.value === "costo";
  document.querySelectorAll(".transaction-expense-field").forEach((field) => { field.hidden = isCost; });
  document.querySelectorAll(".transaction-cost-field").forEach((field) => { field.hidden = !isCost; });
});
document.querySelector("#make-recurring").addEventListener("change", (event) => {
  document.querySelector("#recurrence-fields").hidden = !event.currentTarget.checked;
  document.querySelector("#transaction-file").closest("div").hidden = event.currentTarget.checked;
});
transactionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  showTransactionFeedback(transactionFeedback, "");
  const isCost = document.querySelector("#transaction-type").value === "costo";
  const recurring = document.querySelector("#make-recurring").checked;
  const payload = {
    type: isCost ? "costo" : "gasto",
    amount: document.querySelector("#transaction-amount").value,
    date: document.querySelector("#transaction-date").value,
    description: document.querySelector("#transaction-description").value.trim(),
    vendor: document.querySelector("#transaction-vendor").value.trim(),
  };
  if (isCost) payload.cost_type = document.querySelector("#transaction-cost-type").value;
  else {
    payload.category = document.querySelector("#transaction-category").value;
    payload.nature = document.querySelector("#transaction-nature").value;
  }
  const fileId = document.querySelector("#transaction-file").value;
  if (fileId && !recurring) payload.file_id = fileId;
  if (recurring) {
    payload.frequency = document.querySelector("#recurrence-frequency").value;
    payload.interval = Number(document.querySelector("#recurrence-interval").value);
  }

  const submitButton = transactionForm.querySelector(".transaction-submit");
  submitButton.disabled = true;
  try {
    const response = await apiFetch(
      recurring ? "/api/recurring-transactions" : "/api/transactions",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      },
    );
    await responseError(response, "No se pudo guardar la transacción.");
    transactionForm.reset();
    document.querySelector("#transaction-date").value = localDateString();
    document.querySelector("#recurrence-fields").hidden = true;
    document.querySelector("#transaction-file").closest("div").hidden = false;
    document.querySelectorAll(".transaction-expense-field").forEach((field) => { field.hidden = false; });
    document.querySelectorAll(".transaction-cost-field").forEach((field) => { field.hidden = true; });
    showTransactionFeedback(transactionFeedback, recurring
      ? "Transacción registrada y recurrencia programada."
      : "Transacción guardada correctamente.");
    await Promise.all([loadTransactions(), loadRecurringTransactions(), loadFiles()]);
  } catch (error) {
    showTransactionFeedback(transactionFeedback, error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});
document.querySelector("#bank-import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showTransactionFeedback(bankFeedback, "");
  const csvFile = document.querySelector("#bank-csv-file").files[0];
  if (!csvFile) return;
  if (csvFile.size > 5 * 1024 * 1024) {
    showTransactionFeedback(bankFeedback, "El archivo supera el límite de 5 MB.", true);
    return;
  }
  const formData = new FormData();
  formData.append("file", csvFile);
  const submitButton = event.currentTarget.querySelector(".bank-import-button");
  submitButton.disabled = true;
  try {
    const response = await apiFetch("/api/transactions/import", { method: "POST", body: formData });
    const result = await responseError(response, "No se pudo importar el extracto.");
    const details = [
      `${result.imported} movimiento(s) importado(s)`,
      `${result.skipped} duplicado(s) omitido(s)`,
      `${result.errors.length} fila(s) rechazada(s)`,
    ];
    if (result.errors.length) {
      details.push(result.errors.slice(0, 3).map((item) => `Fila ${item.line}: ${item.error}`).join("; "));
    }
    showTransactionFeedback(bankFeedback, details.join(". "), result.errors.length > 0);
    event.currentTarget.reset();
    await Promise.all([loadTransactions(), loadFiles()]);
  } catch (error) {
    showTransactionFeedback(bankFeedback, error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});
document.querySelector("#link-expense").addEventListener("change", (event) => {
  document.querySelector("#expense-fields").hidden = !event.currentTarget.checked;
});
document.querySelector("#dialog-close").addEventListener("click", () => documentDialog.close());
document.querySelector("#dialog-cancel").addEventListener("click", () => documentDialog.close());
document.querySelector("#document-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!activeFile) return;
  const linkExpense = document.querySelector("#link-expense").checked;
  const payload = {
    document_type: document.querySelector("#edit-document-type").value,
    expense: linkExpense ? {
      vendor: document.querySelector("#expense-vendor").value,
      amount: document.querySelector("#expense-amount").value,
      date: document.querySelector("#expense-date").value,
      category: document.querySelector("#expense-category").value,
    } : null,
  };
  const saveButton = event.currentTarget.querySelector(".dialog-save");
  saveButton.disabled = true;
  try {
    const response = await apiFetch(`/api/files/${encodeURIComponent(activeFile.id)}/metadata`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await responseError(response, "No se pudo guardar la clasificación.");
    documentDialog.close();
    showFeedback(payload.expense ? "Documento vinculado al gasto." : "Clasificación del documento guardada.");
    await loadFiles();
  } catch (error) {
    const dialogFeedback = document.querySelector("#document-feedback");
    dialogFeedback.textContent = error.message;
    dialogFeedback.hidden = false;
  } finally {
    saveButton.disabled = false;
  }
});
document.querySelector("#passkey-enable-button").addEventListener("click", async () => {
  try {
    const optionResponse = await apiFetch("/api/auth/passkeys/register/options", { method: "POST" });
    const options = await responseError(optionResponse, "No se pudo iniciar el registro de passkey.");
    options.challenge = decodeBase64Url(options.challenge);
    options.user.id = decodeBase64Url(options.user.id);
    options.excludeCredentials = options.excludeCredentials.map((item) => ({
      ...item,
      id: decodeBase64Url(item.id),
    }));
    const credential = await navigator.credentials.create({ publicKey: options });
    if (!credential) throw new Error("No se completó el registro biométrico.");
    const verifyResponse = await apiFetch("/api/auth/passkeys/register/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentialPayload(credential)),
    });
    await responseError(verifyResponse, "No se pudo registrar la passkey.");
    document.querySelector("#passkey-enable-button").hidden = true;
    alert("Huella o Face ID activados para este dispositivo.");
  } catch (error) {
    alert(error.message);
  }
});
document.querySelector("#logout-button").addEventListener("click", async () => {
  try {
    const response = await apiFetch("/api/auth/logout", { method: "POST" });
    await responseError(response, "No se pudo cerrar la sesión.");
    csrfToken = "";
    const statusResponse = await fetch("/api/auth/status");
    const status = await responseError(statusResponse, "No se pudo comprobar la sesión.");
    files = [];
    fileList.replaceChildren();
    expenseList.replaceChildren();
    document.querySelector("#transaction-expense-list").replaceChildren();
    document.querySelector("#transaction-cost-list").replaceChildren();
    document.querySelector("#recurring-list").replaceChildren();
    document.querySelector("#budget-list").replaceChildren();
    document.querySelector("#budget-alerts").replaceChildren();
    document.querySelector("#budget-alerts").hidden = true;
    document.querySelector("#budget-empty").hidden = false;
    categorySpending = [];
    updateScenarioProjection();
    expenseEmpty.hidden = false;
    updateSummary();
    showLogin(status);
  } catch (error) {
    showFeedback(error.message, true);
  }
});

document.querySelector("#browse-button").addEventListener("click", openFilePicker);
document.querySelector("#select-button").addEventListener("click", openFilePicker);
dropzone.addEventListener("click", (event) => {
  if (!event.target.closest("button")) openFilePicker();
});
dropzone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    openFilePicker();
  }
});
fileInput.addEventListener("change", () => uploadFiles(fileInput.files));
searchInput.addEventListener("input", renderFiles);

function updateActiveNavigation() {
  const links = [...document.querySelectorAll(".sidebar nav .nav-link")];
  const requestedHash = window.location.hash || "#overview";
  const currentLink = links.find((link) => link.getAttribute("href") === requestedHash)
    || links.find((link) => link.getAttribute("href") === "#overview");
  const currentHash = currentLink.getAttribute("href");
  document.body.dataset.view = currentHash.slice(1);
  const icon = currentLink.querySelector(".nav-icon");
  document.querySelector("#current-page-label").textContent = currentLink.textContent
    .replace(icon.textContent, "")
    .trim();
  links.forEach((link) => {
    const isActive = link === currentLink;
    link.classList.toggle("active", isActive);
    if (isActive) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

window.addEventListener("hashchange", updateActiveNavigation);
updateActiveNavigation();

for (const eventName of ["dragenter", "dragover"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("dragover");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragover");
  });
}
dropzone.addEventListener("drop", (event) => uploadFiles(event.dataTransfer.files));

populateCategorySelect(document.querySelector("#budget-category"), "gasto");
populateCategorySelect(document.querySelector("#scenario-category"), "gasto");
updateScenarioProjection();
initializeAuth();
