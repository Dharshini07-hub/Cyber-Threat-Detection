import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

// Display timestamps consistently in India Standard Time (IST).
// Timestamp strings without an explicit timezone are treated as UTC,
// matching the backend's format_timestamp_ist() behavior.
function formatTimestampIST(value, timeOnly = false) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }

  const rawValue = String(value).trim();
  if (!rawValue) return "-";

  let normalizedValue = rawValue;

  // Normalize common SQL-style timestamps before parsing.
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}/.test(normalizedValue)) {
    normalizedValue = normalizedValue.replace(" ", "T");
  }

  // Treat timezone-naive ISO-like timestamps as UTC for consistency.
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(normalizedValue);
  if (!hasTimezone && /^\d{4}-\d{2}-\d{2}T/.test(normalizedValue)) {
    normalizedValue += "Z";
  }

  const parsedDate = new Date(normalizedValue);
  if (Number.isNaN(parsedDate.getTime())) {
    return rawValue;
  }

  const options = timeOnly
    ? {
        timeZone: "Asia/Kolkata",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      }
    : {
        timeZone: "Asia/Kolkata",
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true,
      };

  const formatted = new Intl.DateTimeFormat("en-IN", options).format(parsedDate);
  return timeOnly ? formatted : `${formatted} IST`;
}


function App() {
  const [activePage, setActivePage] = useState("Dashboard");

  // ================= NEON AUTHENTICATION =================
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [resetToken, setResetToken] = useState(() => new URLSearchParams(window.location.search).get("reset_token") || "");
  const [authMode, setAuthMode] = useState(() => new URLSearchParams(window.location.search).get("reset_token") ? "reset" : "login");
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [authMessage, setAuthMessage] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [authToken, setAuthToken] = useState(() => sessionStorage.getItem("cowrie_auth_token") || "");
  const [notificationEnabled, setNotificationEnabled] = useState(true);
  const [notificationBusy, setNotificationBusy] = useState(false);
  const [notificationMessage, setNotificationMessage] = useState("");

  useEffect(() => {
    if (!authToken) return;
    let cancelled = false;
    fetch(`${API_BASE}/api/auth/me`, { headers: { Authorization: `Bearer ${authToken}` } })
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.message || "Your session has expired. Please log in again.");
        if (!cancelled) {
          setLoginEmail(data.user?.email || "");
          setNotificationEnabled(Boolean(data.user?.notification_enabled));
          setIsLoggedIn(true);
        }
      })
      .catch(() => {
        sessionStorage.removeItem("cowrie_auth_token");
        if (!cancelled) { setAuthToken(""); setIsLoggedIn(false); }
      });
    return () => { cancelled = true; };
  }, [authToken]);

  const handleLogin = async (event) => {
    event.preventDefault();
    setLoginError(""); setAuthMessage("");
    if (!loginEmail.trim() || !loginPassword) { setLoginError("Please enter email and password."); return; }
    setAuthBusy(true);
    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail.trim(), password: loginPassword })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.message || "Login failed.");
      sessionStorage.setItem("cowrie_auth_token", data.token);
      setAuthToken(data.token);
      setLoginEmail(data.user.email);
      setNotificationEnabled(Boolean(data.user.notification_enabled));
      setIsLoggedIn(true); setActivePage("Dashboard"); setLoginPassword("");
    } catch (error) { setLoginError(error.message || "Unable to connect to the backend."); }
    finally { setAuthBusy(false); }
  };

  const handleRegister = async (event) => {
    event.preventDefault();
    setLoginError(""); setAuthMessage("");
    if (!loginEmail.trim() || !registerPassword) { setLoginError("Enter your email and password."); return; }
    if (registerPassword.length < 8) { setLoginError("Password must contain at least 8 characters."); return; }
    if (registerPassword !== confirmPassword) { setLoginError("Passwords do not match."); return; }
    setAuthBusy(true);
    try {
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail.trim(), password: registerPassword })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok && response.status !== 202) throw new Error(data.message || "Registration failed.");
      setAuthMessage(data.message || "Registration submitted. Check your email for verification.");
      setAuthMode("login"); setRegisterPassword(""); setConfirmPassword(""); setLoginPassword("");
    } catch (error) { setLoginError(error.message || "Unable to register."); }
    finally { setAuthBusy(false); }
  };

  const handleRequestPasswordReset = async (event) => {
    event.preventDefault();
    setLoginError(""); setAuthMessage("");
    if (!loginEmail.trim()) { setLoginError("Enter your registered email address."); return; }
    setAuthBusy(true);
    try {
      const response = await fetch(`${API_BASE}/api/auth/request-password-reset`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail.trim() })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.message || "Could not request a password reset.");
      setAuthMessage(data.message || "If a verified account exists, a reset link has been sent.");
    } catch (error) {
      setLoginError(error.message || "Unable to connect to the backend.");
    } finally { setAuthBusy(false); }
  };

  const handleResetPassword = async (event) => {
    event.preventDefault();
    setLoginError(""); setAuthMessage("");
    if (!resetToken) { setLoginError("The reset link is missing. Request a new password reset email."); return; }
    if (registerPassword.length < 8) { setLoginError("Password must contain at least 8 characters."); return; }
    if (registerPassword !== confirmPassword) { setLoginError("Passwords do not match."); return; }
    setAuthBusy(true);
    try {
      const response = await fetch(`${API_BASE}/api/auth/reset-password`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: resetToken, password: registerPassword })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.message || "Password reset failed.");
      setAuthMessage(data.message || "Password updated. You can now sign in.");
      setAuthMode("login"); setResetToken(""); setRegisterPassword(""); setConfirmPassword(""); setLoginPassword("");
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch (error) {
      setLoginError(error.message || "Unable to reset password.");
    } finally { setAuthBusy(false); }
  };

  const handleResendVerification = async () => {
    setLoginError(""); setAuthMessage("");
    if (!loginEmail.trim()) { setLoginError("Enter your registered email address first."); return; }
    setAuthBusy(true);
    try {
      const response = await fetch(`${API_BASE}/api/auth/resend-verification`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail.trim() })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.message || "Could not resend verification email.");
      setAuthMessage(data.message || "If the account is pending verification, a new email has been sent.");
    } catch (error) { setLoginError(error.message || "Could not resend verification email."); }
    finally { setAuthBusy(false); }
  };

  const handleNotificationToggle = async (enabled) => {
    if (!authToken) return;
    setNotificationBusy(true); setNotificationMessage("");
    try {
      const response = await fetch(`${API_BASE}/api/auth/notification-preference`, {
        method: "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({ notification_enabled: enabled })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.message || "Could not update notification preference.");
      setNotificationEnabled(Boolean(data.notification_enabled));
      setNotificationMessage("Preference saved.");
    } catch (error) { setNotificationMessage(error.message || "Update failed."); }
    finally { setNotificationBusy(false); }
  };

  const handleLogout = () => {
    sessionStorage.removeItem("cowrie_auth_token");
    setAuthToken(""); setIsLoggedIn(false); setLoginPassword("");
    setLoginError(""); setAuthMessage(""); setNotificationMessage("");
    setActivePage("Dashboard");
  };

  const [attackLogs, setAttackLogs] = useState([]);
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveEventCount, setLiveEventCount] = useState(0);
  const [summary, setSummary] = useState(null);
  const [activityData, setActivityData] = useState([]);
  const [riskAnalysis, setRiskAnalysis] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [alertsLoading, setAlertsLoading] = useState(true);
  const [alertMeta, setAlertMeta] = useState(null);

  const [loading, setLoading] = useState(true);
  const [riskLoading, setRiskLoading] = useState(true);
  const [apiError, setApiError] = useState("");

  const [searchText, setSearchText] = useState("");
  const [selectedRisk, setSelectedRisk] = useState("All");
  const [selectedLog, setSelectedLog] = useState(null);
  const [selectedRiskEvent, setSelectedRiskEvent] = useState(null);
  const [blockingIp, setBlockingIp] = useState("");
  const [blockMessage, setBlockMessage] = useState("");

  // Live Cowrie refresh trigger
  const [liveRefreshTick, setLiveRefreshTick] = useState(0);
  const LIVE_REFRESH_INTERVAL = 3000;

  // ================= SHAP EXPLANATION =================

  const [shapExplanation, setShapExplanation] = useState(null);
  const [shapLoading, setShapLoading] = useState(false);
  const [shapError, setShapError] = useState("");


  // ================= UPLOADED DATASET ANALYSIS =================

  const [datasetFile, setDatasetFile] = useState(null);
  const [datasetAnalysis, setDatasetAnalysis] = useState(null);
  const [datasetLoading, setDatasetLoading] = useState(false);
  const [datasetError, setDatasetError] = useState("");
  const [datasetSuccess, setDatasetSuccess] = useState("");
  const [datasetSearch, setDatasetSearch] = useState("");
  const [datasetRiskFilter, setDatasetRiskFilter] = useState("All");

  const navigationItems = [
    "Dashboard",
    "Attack Logs",
    "Risk Analysis",
    "Dataset Analysis",
    "Alerts",
  ];

  // ================= LIVE DASHBOARD REFRESH =================

  useEffect(() => {
    if (!isLoggedIn) return;

    const interval = setInterval(() => {
      setLiveRefreshTick((tick) => tick + 1);
    }, LIVE_REFRESH_INTERVAL);

    return () => clearInterval(interval);
  }, [isLoggedIn]);

  // ================= LOAD COWRIE LOG DATA =================

  useEffect(() => {
    if (!isLoggedIn) return;

    fetch(`${API_BASE}/api/logs?limit=100`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Backend request failed");
        }

        return response.json();
      })
      .then((result) => {
        if (result.status !== "success") {
          throw new Error(result.message || "API error");
        }

        setAttackLogs(result.data);
        setApiError("");
      })
      .catch((error) => {
        console.error("Cowrie logs API error:", error);

        setApiError(
          "Cowrie is not connected. Start the Cowrie honeypot to receive attack data."
        );
      });
  }, [isLoggedIn, liveRefreshTick]);

  // ================= LOAD PERSISTENT LIVE COWRIE EVENTS =================

  useEffect(() => {
    if (!isLoggedIn) return;

    fetch(`${API_BASE}/api/live-logs?limit=50`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Live Cowrie request failed");
        }

        return response.json();
      })
      .then((result) => {
        if (result.status !== "success") {
          throw new Error(result.message || "Live Cowrie API error");
        }

        setLiveEvents(Array.isArray(result.data) ? result.data : []);
        setLiveEventCount(Number(result.total_live_events) || 0);
      })
      .catch((error) => {
        console.error("Live Cowrie API error:", error);
      });
  }, [isLoggedIn, liveRefreshTick]);

  // ================= LOAD COMPLETE DATASET SUMMARY =================

  useEffect(() => {
    if (!isLoggedIn) return;

    fetch(`${API_BASE}/api/summary`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Summary request failed");
        }

        return response.json();
      })
      .then((result) => {
        if (result.status !== "success") {
          throw new Error(result.message || "Summary API error");
        }

        setSummary(result);
        setApiError("");
        setLoading(false);
      })
      .catch((error) => {
        console.error("Cowrie summary API error:", error);

        setApiError(
          "Cowrie is not connected. Start the Cowrie honeypot to receive attack data."
        );

        setLoading(false);
      });
  }, [isLoggedIn, liveRefreshTick]);

  // ================= LOAD REAL ATTACK ACTIVITY =================

  useEffect(() => {
    if (!isLoggedIn) return;

    fetch(`${API_BASE}/api/activity`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Activity request failed");
        }

        return response.json();
      })
      .then((result) => {
        if (result.status !== "success") {
          throw new Error(result.message || "Activity API error");
        }

        setActivityData(result.data);
      })
      .catch((error) => {
        console.error("Cowrie activity API error:", error);

        setApiError(
          "Cowrie is not connected. Start the Cowrie honeypot to receive attack data."
        );
      });
  }, [isLoggedIn, liveRefreshTick]);

  // ================= LOAD EXPLAINABLE RISK ANALYSIS =================

  useEffect(() => {
    if (!isLoggedIn) return;

    fetch(`${API_BASE}/api/risk-analysis?limit=100`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Risk analysis request failed");
        }

        return response.json();
      })
      .then((result) => {
        if (result.status !== "success") {
          throw new Error(result.message || "Risk analysis API error");
        }

        setRiskAnalysis(result.data);
        setRiskLoading(false);
      })
      .catch((error) => {
        console.error("Risk analysis API error:", error);

        setRiskLoading(false);

        setApiError(
          "Cowrie is not connected. Start the Cowrie honeypot to receive attack data."
        );
      });
  }, [isLoggedIn, liveRefreshTick]);

  // ================= LOAD REAL BACKEND ALERTS =================

  useEffect(() => {
    if (!isLoggedIn) return;

    fetch(`${API_BASE}/api/alerts?limit=100`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Alerts request failed");
        }

        return response.json();
      })
      .then((result) => {
        if (result.status !== "success") {
          throw new Error(result.message || "Alerts API error");
        }

        setAlerts(Array.isArray(result.data) ? result.data : []);
        setAlertMeta(result);
        setAlertsLoading(false);
      })
      .catch((error) => {
        console.error("Cowrie alerts API error:", error);

        setAlertsLoading(false);

        setApiError(
          "Cowrie is not connected. Start the Cowrie honeypot to receive attack data."
        );
      });
  }, [isLoggedIn, liveRefreshTick]);

  // ================= COMPLETE DATASET VALUES =================

  const totalEvents = summary?.total_events ?? 0;
  const attackEvents = summary?.attack_events ?? 0;

  const lowRisk = summary?.risk_summary?.low ?? 0;
  const mediumRisk = summary?.risk_summary?.medium ?? 0;
  const highRisk = summary?.risk_summary?.high ?? 0;
  const criticalRisk = summary?.risk_summary?.critical ?? 0;

  // ================= RISK PERCENTAGES =================

  const lowPercentage =
    totalEvents > 0 ? ((lowRisk / totalEvents) * 100).toFixed(1) : "0.0";

  const mediumPercentage =
    totalEvents > 0
      ? ((mediumRisk / totalEvents) * 100).toFixed(1)
      : "0.0";

  const highPercentage =
    totalEvents > 0 ? ((highRisk / totalEvents) * 100).toFixed(1) : "0.0";

  const criticalPercentage =
    totalEvents > 0
      ? ((criticalRisk / totalEvents) * 100).toFixed(1)
      : "0.0";

  // ================= CALCULATED RISK COUNTS =================

  const calculatedLow = riskAnalysis.filter(
    (log) => log.calculated_risk_level === "Low"
  ).length;

  const calculatedMedium = riskAnalysis.filter(
    (log) => log.calculated_risk_level === "Medium"
  ).length;

  const calculatedHigh = riskAnalysis.filter(
    (log) => log.calculated_risk_level === "High"
  ).length;

  const calculatedCritical = riskAnalysis.filter(
    (log) => log.calculated_risk_level === "Critical"
  ).length;

  const calculatedTotal =
    calculatedLow + calculatedMedium + calculatedHigh + calculatedCritical;

  const calculatedLowPercentage =
    calculatedTotal > 0
      ? ((calculatedLow / calculatedTotal) * 100).toFixed(1)
      : "0.0";

  const calculatedMediumPercentage =
    calculatedTotal > 0
      ? ((calculatedMedium / calculatedTotal) * 100).toFixed(1)
      : "0.0";

  const calculatedHighPercentage =
    calculatedTotal > 0
      ? ((calculatedHigh / calculatedTotal) * 100).toFixed(1)
      : "0.0";

  const calculatedCriticalPercentage =
    calculatedTotal > 0
      ? ((calculatedCritical / calculatedTotal) * 100).toFixed(1)
      : "0.0";

  const getSystemResponse = (event) => {
    const level = String(
      event?.calculated_risk_level || event?.risk_level || ""
    ).toLowerCase();

    const emailStatus = String(
      event?.email_notification?.status || ""
    ).toLowerCase();

    if (level === "critical") {
      if (emailStatus === "sent") {
        return "Email notification sent";
      }

      if (emailStatus === "not_configured") {
        return "Critical risk detected; email notification is not configured";
      }

      return "Critical risk detected";
    }

    if (level === "high") {
      if (emailStatus === "sent") {
        return "Email notification sent";
      }

      if (emailStatus === "not_configured") {
        return "High-risk activity detected; email notification is not configured";
      }

      return "High-risk activity detected";
    }

    return "Continue monitoring";
  };

  const calculatedRiskBars = [
    { label: "Low", count: calculatedLow, percentage: calculatedLowPercentage },
    { label: "Medium", count: calculatedMedium, percentage: calculatedMediumPercentage },
    { label: "High", count: calculatedHigh, percentage: calculatedHighPercentage },
    { label: "Critical", count: calculatedCritical, percentage: calculatedCriticalPercentage },
  ];

  // ================= SEARCH + FILTER =================

  const filteredLogs = attackLogs.filter((log) => {
    const search = searchText.toLowerCase();

    const matchesSearch =
      String(log.timestamp || "").toLowerCase().includes(search) ||
      String(log.src_ip || "").toLowerCase().includes(search) ||
      String(log.event_id || "").toLowerCase().includes(search) ||
      String(log.attack_type || "").toLowerCase().includes(search) ||
      String(log.command_input || "").toLowerCase().includes(search) ||
      String(log.explanation || "").toLowerCase().includes(search);

    const matchesRisk =
      selectedRisk === "All" ||
      String(log.risk_level || "").toLowerCase() ===
        selectedRisk.toLowerCase();

    return matchesSearch && matchesRisk;
  });

  // ================= RECENT LOGS =================

  const recentLogs = attackLogs.slice(0, 5);

  const getLiveRiskLevel = (event) =>
    String(
      event?.calculated_risk_level ||
        event?.risk_level ||
        "Low"
    );

  const getLiveRiskScore = (event) =>
    event?.calculated_risk_score ??
    event?.risk_score ??
    "-";

  // ================= RECENT CRITICAL ALERTS =================

  const recentAlerts = attackLogs
    .filter(
      (log) =>
        String(log.risk_level || "").toLowerCase() === "critical"
    )
    .slice(0, 3);

  // ================= CALCULATED ALERTS =================

  // Alert-worthy events are taken from the new explainable risk assessment.
  // High-risk events are intended to trigger a system email notification to the security analyst.
  // Critical-risk events are intended to trigger a system alert and IP-blocking response.
  // The actual email sender and firewall blocking modules are implemented separately.
  // Critical risk events require an alert + block recommendation.
  const calculatedAlerts = riskAnalysis
    .filter((log) => {
      const level = String(log.calculated_risk_level || "").toLowerCase();
      return level === "high" || level === "critical";
    })
    .sort((a, b) => {
      const priority = { critical: 2, high: 1 };
      const levelA = String(a.calculated_risk_level || "").toLowerCase();
      const levelB = String(b.calculated_risk_level || "").toLowerCase();

      if ((priority[levelB] || 0) !== (priority[levelA] || 0)) {
        return (priority[levelB] || 0) - (priority[levelA] || 0);
      }

      return String(b.timestamp || "").localeCompare(
        String(a.timestamp || "")
      );
    });

  const calculatedCriticalAlerts = calculatedAlerts.filter(
    (log) =>
      String(log.calculated_risk_level || "").toLowerCase() === "critical"
  );

  const calculatedEmailAlerts = calculatedAlerts.filter(
    (log) =>
      String(log.calculated_risk_level || "").toLowerCase() === "high"
  );

  // ================= BACKEND ALERT VALUES =================

  const getAlertLevel = (alert) =>
    String(
      alert?.calculated_risk_level ||
        alert?.risk_level ||
        alert?.level ||
        ""
    ).toLowerCase();

  const backendCriticalAlerts = alerts.filter(
    (alert) => getAlertLevel(alert) === "critical"
  );

  const backendHighAlerts = alerts.filter(
    (alert) => getAlertLevel(alert) === "high"
  );

  const backendAlertCount = alerts.length;

  // ================= REAL ATTACK ACTIVITY =================

  const activityBuckets = activityData.map((item) => ({
    label: item.time ? formatTimestampIST(item.time, true) : "-",
    count: Number(item.events) || 0,
  }));

  const maximumActivity = Math.max(
    ...activityBuckets.map((bucket) => bucket.count),
    1
  );

  // ================= ATTACK LOG DETAILS =================

  const openLogDetails = (log) => {
    setSelectedLog(log);
  };

  const closeLogDetails = () => {
    setSelectedLog(null);
  };

  // ================= RISK EVENT DETAILS =================

  const openRiskDetails = (log) => {
    setSelectedRiskEvent(log);
  };

  const closeRiskDetails = () => {
    setSelectedRiskEvent(null);
    setBlockMessage("");
    setShapExplanation(null);
    setShapError("");
  };

  // ================= LOAD SHAP EXPLANATION =================

  useEffect(() => {
    if (!isLoggedIn || !selectedRiskEvent) {
      setShapExplanation(null);
      setShapError("");
      return;
    }

    const liveEventKey =
      selectedRiskEvent.live_event_key ||
      selectedRiskEvent.event_key ||
      "";

    const datasetIndex =
      selectedRiskEvent.dataset_index ??
      selectedRiskEvent.record_number ??
      selectedRiskEvent.index;

    if (!liveEventKey && (datasetIndex === undefined || datasetIndex === null || datasetIndex === "")) {
      setShapExplanation(null);
      setShapError("No live event key or dataset index is available for this event.");
      return;
    }

    setShapLoading(true);
    setShapError("");
    setShapExplanation(null);

    const shapUrl = liveEventKey
      ? `${API_BASE}/api/shap-explanation?event_key=${encodeURIComponent(
          liveEventKey
        )}`
      : `${API_BASE}/api/shap-explanation?index=${encodeURIComponent(
          datasetIndex
        )}`;

    fetch(shapUrl)
      .then((response) => {
        if (!response.ok) {
          throw new Error("SHAP explanation request failed");
        }
        return response.json();
      })
      .then((result) => {
        if (result.status !== "success") {
          throw new Error(result.message || "SHAP explanation API error");
        }

        setShapExplanation(result.data || null);
      })
      .catch((error) => {
        console.error("SHAP explanation API error:", error);
        setShapError(
          error.message ||
            "Unable to load SHAP explanation for this event."
        );
      })
      .finally(() => {
        setShapLoading(false);
      });
  }, [isLoggedIn, selectedRiskEvent]);

  // ================= MANUAL IP BLOCKING =================

  const handleBlockIp = async (ipAddress) => {
    const ip = String(ipAddress || "").trim();

    if (!ip) {
      setBlockMessage("No source IP is available for this event.");
      return;
    }

    if (blockingIp) return;

    setBlockingIp(ip);
    setBlockMessage("Blocking IP...");

    try {
      const response = await fetch(`${API_BASE}/api/block-ip`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ src_ip: ip }),
      });

      const result = await response.json();

      if (!response.ok || result.status !== "success") {
        throw new Error(result.message || "IP blocking request failed");
      }

      setBlockMessage(
        result.message || `IP ${ip} was blocked successfully.`
      );
    } catch (error) {
      console.error("IP blocking API error:", error);
      setBlockMessage(
        error.message ||
          "Unable to block the IP address. Make sure the blocking service is available."
      );
    } finally {
      setBlockingIp("");
    }
  };

  // ================= UPLOAD AND ANALYSE CSV =================

  const handleDatasetAnalysis = async (event) => {
    event.preventDefault();

    if (!datasetFile) {
      setDatasetError("Choose a CSV file before starting the analysis.");
      setDatasetSuccess("");
      return;
    }

    if (!datasetFile.name.toLowerCase().endsWith(".csv")) {
      setDatasetError("Only CSV files are supported.");
      setDatasetSuccess("");
      return;
    }

    if (datasetFile.size > 5 * 1024 * 1024) {
      setDatasetError("The selected file exceeds the 5 MB limit.");
      setDatasetSuccess("");
      return;
    }

    const formData = new FormData();
    formData.append("file", datasetFile);
    setDatasetLoading(true);
    setDatasetError("");
    setDatasetSuccess("");

    try {
      const response = await fetch(
        `${API_BASE}/api/analyse-dataset`,
        { method: "POST", body: formData }
      );
      const result = await response.json();

      if (!response.ok || result.status !== "success") {
        throw new Error(result.message || "Dataset analysis failed.");
      }

      setDatasetAnalysis(result);
      setDatasetSearch("");
      setDatasetRiskFilter("All");
      setDatasetSuccess(result.message || "Dataset analysed successfully.");
    } catch (error) {
      setDatasetAnalysis(null);
      setDatasetError(
        error.message ||
          "Unable to analyse the uploaded dataset. Check that the Flask backend is running."
      );
    } finally {
      setDatasetLoading(false);
    }
  };

  const clearDatasetAnalysis = () => {
    setDatasetFile(null);
    setDatasetAnalysis(null);
    setDatasetError("");
    setDatasetSuccess("");
    setDatasetSearch("");
    setDatasetRiskFilter("All");
  };

  const uploadedDatasetRecords = Array.isArray(datasetAnalysis?.data)
    ? datasetAnalysis.data
    : [];

  const filteredDatasetRecords = uploadedDatasetRecords.filter((record) => {
    const search = datasetSearch.trim().toLowerCase();
    const level = String(record.calculated_risk_level || "");
    const matchesRisk =
      datasetRiskFilter === "All" ||
      level.toLowerCase() === datasetRiskFilter.toLowerCase();
    const searchableText = [
      record.timestamp,
      record.src_ip,
      record.event_id,
      record.event_type,
      record.attack_type,
      record.command_input,
      record.command,
      record.input,
      record.explanation,
      ...(Array.isArray(record.risk_reasons) ? record.risk_reasons : []),
    ]
      .map((value) => String(value ?? ""))
      .join(" ")
      .toLowerCase();

    return matchesRisk && searchableText.includes(search);
  });

  if (!isLoggedIn) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#f5f6f8",
          padding: "24px",
          boxSizing: "border-box",
        }}
      >
        <div
          style={{
            width: "100%",
            maxWidth: "420px",
            background: "#ffffff",
            border: "1px solid #d9dde3",
            borderRadius: "8px",
            padding: "36px",
            boxSizing: "border-box",
            boxShadow: "0 8px 24px rgba(0, 0, 0, 0.06)",
          }}
        >
          <div style={{ marginBottom: "28px" }}>
            <h1
              style={{
                margin: "0 0 8px",
                fontSize: "24px",
                color: "#20242b",
              }}
            >
              Cyber Threat Detection
            </h1>

            <p
              style={{
                margin: 0,
                color: "#667085",
                fontSize: "14px",
              }}
            >
              Cowrie Honeypot Security Dashboard
            </p>
          </div>

          <form onSubmit={authMode === "login" ? handleLogin : authMode === "register" ? handleRegister : authMode === "forgot" ? handleRequestPasswordReset : handleResetPassword}>
            {authMode !== "reset" && <>
              <label style={{ display: "block", marginBottom: "7px", fontSize: "14px", fontWeight: 600, color: "#344054" }}>Email</label>
              <input type="email" required value={loginEmail} onChange={(event) => { setLoginEmail(event.target.value); setLoginError(""); }} placeholder="Enter your email address" autoComplete="email" style={{ width: "100%", padding: "11px 12px", border: "1px solid #cfd4da", borderRadius: "5px", marginBottom: "16px", boxSizing: "border-box", fontSize: "14px" }} />
            </>}
            {(authMode === "login" || authMode === "register") && <>
              <label style={{ display: "block", marginBottom: "7px", fontSize: "14px", fontWeight: 600, color: "#344054" }}>Password</label>
              <input type="password" required value={authMode === "login" ? loginPassword : registerPassword} onChange={(event) => authMode === "login" ? setLoginPassword(event.target.value) : setRegisterPassword(event.target.value)} placeholder="Enter password" autoComplete={authMode === "login" ? "current-password" : "new-password"} style={{ width: "100%", padding: "11px 12px", border: "1px solid #cfd4da", borderRadius: "5px", marginBottom: "12px", boxSizing: "border-box", fontSize: "14px" }} />
            </>}
            {(authMode === "register" || authMode === "reset") && <>
              {authMode === "reset" && <label style={{ display: "block", marginBottom: "7px", fontSize: "14px", fontWeight: 600, color: "#344054" }}>New password</label>}
              {authMode === "reset" && <input type="password" required minLength={8} value={registerPassword} onChange={(event) => setRegisterPassword(event.target.value)} placeholder="Enter new password" autoComplete="new-password" style={{ width: "100%", padding: "11px 12px", border: "1px solid #cfd4da", borderRadius: "5px", marginBottom: "12px", boxSizing: "border-box", fontSize: "14px" }} />}
              <label style={{ display: "block", marginBottom: "7px", fontSize: "14px", fontWeight: 600, color: "#344054" }}>{authMode === "reset" ? "Confirm new password" : "Confirm password"}</label>
              <input type="password" required minLength={8} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Re-enter password" autoComplete="new-password" style={{ width: "100%", padding: "11px 12px", border: "1px solid #cfd4da", borderRadius: "5px", marginBottom: "12px", boxSizing: "border-box", fontSize: "14px" }} />
              {authMode === "register" && <p style={{ color: "#667085", fontSize: "12px", marginBottom: "12px" }}>Use at least 8 characters. Email verification is required before login.</p>}
              {authMode === "reset" && <p style={{ color: "#667085", fontSize: "12px", marginBottom: "12px" }}>Use at least 8 characters. This reset link can only be used once.</p>}
            </>}
            {authMode === "forgot" && <p style={{ color: "#667085", fontSize: "12px", marginBottom: "12px" }}>We will email a one-time password reset link if this address belongs to a verified account.</p>}
            {loginError && <div style={{ marginBottom: "14px", padding: "10px 12px", border: "1px solid #f1c0bc", borderRadius: "5px", background: "#fff7f6", color: "#b42318", fontSize: "13px" }}>{loginError}</div>}
            {authMessage && <div style={{ marginBottom: "14px", padding: "10px 12px", border: "1px solid #b7dfc5", borderRadius: "5px", background: "#f2fbf5", color: "#176b37", fontSize: "13px" }}>{authMessage}</div>}
            <button type="submit" disabled={authBusy} style={{ width: "100%", border: "none", borderRadius: "5px", padding: "11px 14px", background: "#20242b", color: "#ffffff", fontSize: "14px", fontWeight: 600, cursor: authBusy ? "wait" : "pointer", opacity: authBusy ? 0.7 : 1 }}>{authBusy ? "Please wait..." : authMode === "login" ? "Sign In" : authMode === "register" ? "Create Account" : authMode === "forgot" ? "Send Reset Link" : "Update Password"}</button>
          </form>
          <div style={{ marginTop: "16px", textAlign: "center", fontSize: "13px", color: "#475467" }}>
            {authMode === "login" ? <>
              New user? <button type="button" onClick={() => { setAuthMode("register"); setLoginError(""); setAuthMessage(""); }} style={{ border: 0, background: "none", color: "#2456a6", cursor: "pointer", fontWeight: 600 }}>Create an account</button>
              <button type="button" onClick={() => { setAuthMode("forgot"); setLoginError(""); setAuthMessage(""); }} style={{ display: "block", margin: "10px auto 0", border: 0, background: "none", color: "#2456a6", cursor: "pointer", fontWeight: 600 }}>Forgot Password?</button>
            </> : <button type="button" onClick={() => { setAuthMode("login"); setLoginError(""); setAuthMessage(""); }} style={{ border: 0, background: "none", color: "#2456a6", cursor: "pointer", fontWeight: 600 }}>Back to Sign in</button>}
          </div>
          {authMode === "login" && <button type="button" onClick={handleResendVerification} disabled={authBusy} style={{ display: "block", margin: "10px auto 0", border: 0, background: "none", color: "#667085", fontSize: "12px", cursor: "pointer" }}>Resend verification email</button>}
        </div>
      </div>
    );
  }

  return (
    <div className="app">

      {/* ================= SIDEBAR ================= */}

      <aside className="sidebar">

        <div className="project-title">
          <h2>Cyber Threat Detection</h2>
          <p>Cowrie Honeypot</p>
        </div>

        <div
          style={{
            margin: "18px 14px",
            padding: "12px",
            border: "1px solid #343a43",
            borderRadius: "5px",
            color: "#d7dbe0",
            fontSize: "12px",
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: "4px" }}>
            Security Analyst
          </div>
          <div style={{ color: "#9ea5ad", wordBreak: "break-word" }}>
            {loginEmail}
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "12px", cursor: notificationBusy ? "wait" : "pointer" }}>
            <input type="checkbox" checked={notificationEnabled} disabled={notificationBusy} onChange={(event) => handleNotificationToggle(event.target.checked)} />
            <span>Email security alerts</span>
          </label>
          {notificationMessage && <div style={{ color: "#cbd5e1", marginTop: "6px", lineHeight: 1.4 }}>{notificationMessage}</div>}
        </div>

        <nav>
          {navigationItems.map((item) => (
            <button
              key={item}
              className={`nav-item ${
                activePage === item ? "active" : ""
              }`}
              onClick={() => {
                setActivePage(item);
                setSelectedLog(null);
                setSelectedRiskEvent(null);
              }}
            >
              {item}
            </button>
          ))}
        </nav>

        <button
          type="button"
          onClick={handleLogout}
          style={{
            margin: "20px 14px 0",
            width: "calc(100% - 28px)",
            padding: "9px 12px",
            border: "1px solid #454b54",
            borderRadius: "5px",
            background: "transparent",
            color: "#d7dbe0",
            cursor: "pointer",
            fontSize: "13px",
          }}
        >
          Logout
        </button>

      </aside>

      {/* ================= MAIN CONTENT ================= */}

      <main className="main-content">

        {apiError && (
          <div
            className="panel"
            style={{
              marginBottom: "20px",
              borderColor: "#f1c0bc",
              color: "#b42318",
            }}
          >
            {apiError}
          </div>
        )}

        {/* ================================================= */}
        {/* ================= DASHBOARD ===================== */}
        {/* ================================================= */}

        {activePage === "Dashboard" && (
          <>
            <div className="page-header">
              <h1>Dashboard</h1>

              <p>
                Overview of suspicious interactions collected by Cowrie.
              </p>
              <p style={{ marginTop: "6px", fontSize: "12px", color: "#667085" }}>
                Live refresh: every 3 seconds
              </p>
            </div>

            <div className="summary-cards">

              <div className="summary-card">
                <p>Total Events</p>
                <h2>{loading ? "..." : totalEvents}</h2>
              </div>

              <div className="summary-card">
                <p>Attack Events</p>
                <h2>{loading ? "..." : attackEvents}</h2>
              </div>

              <div className="summary-card">
                <p>Critical Risk</p>
                <h2>{loading ? "..." : criticalRisk}</h2>
              </div>

            </div>

            <div className="dashboard-grid">

              <div className="left-column">

                <div className="panel activity-panel">

                  <h3>Attack Activity</h3>

                  <p className="panel-description">
                    Hourly event activity observed through Cowrie.
                  </p>

                  <div className="chart">

                    <div className="y-labels">
                      <span>{maximumActivity}</span>

                      <span>
                        {Math.round(maximumActivity * 0.75)}
                      </span>

                      <span>
                        {Math.round(maximumActivity * 0.5)}
                      </span>

                      <span>0</span>
                    </div>

                    <div
                      style={{
                        display: "flex",
                        alignItems: "flex-end",
                        justifyContent: "space-around",
                        height: "150px",
                        flex: 1,
                        gap: "10px",
                        padding: "10px 20px 0 10px",
                      }}
                    >
                      {activityBuckets.length === 0 ? (
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            width: "100%",
                            height: "100%",
                            color: "#777",
                            fontSize: "13px",
                          }}
                        >
                          Loading activity data...
                        </div>
                      ) : (
                        activityBuckets.map((bucket) => (
                          <div
                            key={bucket.label}
                            style={{
                              display: "flex",
                              flexDirection: "column",
                              alignItems: "center",
                              justifyContent: "flex-end",
                              height: "100%",
                              flex: 1,
                              minWidth: "30px",
                            }}
                          >
                            <span
                              style={{
                                fontSize: "11px",
                                marginBottom: "5px",
                              }}
                            >
                              {bucket.count}
                            </span>

                            <div
                              style={{
                                width: "28px",
                                height: `${
                                  (bucket.count / maximumActivity) * 110
                                }px`,
                                minHeight:
                                  bucket.count > 0 ? "8px" : "2px",
                                background: "#59636f",
                                borderRadius: "3px 3px 0 0",
                              }}
                            />
                          </div>
                        ))
                      )}
                    </div>

                    <div
                      className="x-labels"
                      style={{
                        gap: "10px",
                      }}
                    >
                      {activityBuckets.map((bucket) => (
                        <span key={bucket.label}>
                          {bucket.label}
                        </span>
                      ))}
                    </div>

                  </div>

                </div>

                <div className="panel logs-panel">

                  <h3>Live Cowrie Events</h3>

                  <p className="panel-description">
                    Persistent events received directly from the running Cowrie honeypot.
                    Total stored live events: {liveEventCount}
                  </p>

                  <div className="logs-table">

                    <div className="table-header">
                      <span>Time</span>
                      <span>Source IP</span>
                      <span>Event</span>
                      <span>Risk</span>
                      <span>Score</span>
                    </div>

                    {liveEvents.length === 0 ? (
                      <div className="table-row">
                        <span>Waiting...</span>
                        <span>-</span>
                        <span>-</span>
                        <span>-</span>
                        <span>-</span>
                      </div>
                    ) : (
                      liveEvents.slice(0, 5).map((event, index) => (
                        <div
                          className="table-row"
                          key={`${event.session || event.session_id || "event"}-${event.timestamp || index}-${index}`}
                          onClick={() => openLogDetails(event)}
                          style={{ cursor: "pointer" }}
                        >
                          <span>{formatTimestampIST(event.timestamp_ist || event.timestamp)}</span>
                          <span>{event.src_ip || "-"}</span>
                          <span>{event.event_id || event.attack_type || "-"}</span>

                          <span
                            className={getLiveRiskLevel(event).toLowerCase()}
                          >
                            {getLiveRiskLevel(event)}
                          </span>

                          <span>{getLiveRiskScore(event)}</span>
                        </div>
                      ))
                    )}

                  </div>

                </div>

                <div className="panel logs-panel">

                  <h3>Recent Attack Logs</h3>

                  <p className="panel-description">
                    Latest records from the prepared Cowrie dataset.
                  </p>

                  <div className="logs-table">

                    <div className="table-header">
                      <span>Time</span>
                      <span>Source IP</span>
                      <span>Attack Type</span>
                      <span>Risk</span>
                      <span>Score</span>
                    </div>

                    {loading ? (
                      <div className="table-row">
                        <span>Loading...</span>
                        <span>-</span>
                        <span>-</span>
                        <span>-</span>
                        <span>-</span>
                      </div>
                    ) : (
                      recentLogs.map((log, index) => (
                        <div
                          className="table-row"
                          key={`${log.session_id}-${index}`}
                          onClick={() => openLogDetails(log)}
                          style={{ cursor: "pointer" }}
                        >
                          <span>{formatTimestampIST(log.timestamp_ist || log.timestamp)}</span>

                          <span>{log.src_ip || "-"}</span>

                          <span>{log.attack_type || "-"}</span>

                          <span
                            className={String(
                              log.risk_level || ""
                            ).toLowerCase()}
                          >
                            {log.risk_level || "-"}
                          </span>

                          <span>{log.risk_score ?? "-"}</span>
                        </div>
                      ))
                    )}

                  </div>

                </div>

              </div>

              <div className="right-column">

                <div className="panel risk-panel">

                  <h3>Risk Summary</h3>

                  <p className="panel-description">
                    Risk levels found in the complete Cowrie dataset.
                  </p>

                  <div className="risk-row">
                    <span>Critical Risk</span>
                    <strong>
                      {loading ? "..." : criticalRisk}
                    </strong>
                  </div>

                  <div className="risk-row">
                    <span>High Risk</span>
                    <strong>
                      {loading ? "..." : highRisk}
                    </strong>
                  </div>

                  <div className="risk-row">
                    <span>Medium Risk</span>
                    <strong>
                      {loading ? "..." : mediumRisk}
                    </strong>
                  </div>

                  <div className="risk-row">
                    <span>Low Risk</span>
                    <strong>
                      {loading ? "..." : lowRisk}
                    </strong>
                  </div>

                </div>

                <div className="panel alerts-panel">

                  <h3>Recent Alerts</h3>

                  <p className="panel-description">
                    Critical events requiring attention.
                  </p>

                  {loading ? (
                    <div className="alert-item">
                      <strong>Loading alerts...</strong>
                    </div>
                  ) : recentAlerts.length === 0 ? (
                    <div className="alert-item">
                      <strong>No critical alerts found</strong>
                    </div>
                  ) : (
                    recentAlerts.map((log, index) => (
                      <div
                        className="alert-item"
                        key={`${log.session_id}-${index}`}
                        onClick={() => openLogDetails(log)}
                        style={{ cursor: "pointer" }}
                      >
                        <strong>
                          {log.attack_type || "Critical Activity"}
                        </strong>

                        <p>
                          {log.explanation ||
                            "Critical activity detected."}
                        </p>
                      </div>
                    ))
                  )}

                </div>

              </div>

            </div>

            {/* Dashboard Log Details */}

            {selectedLog && (
              <div
                className="panel event-detail-modal" role="dialog" aria-modal="true" aria-label="Event details"
                style={{
                  marginTop: "20px",
                  border: "1px solid #d9dde3",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "20px",
                  }}
                >
                  <div>
                    <h3>Attack Log Details</h3>

                    <p className="panel-description">
                      Detailed information for the selected Cowrie event.
                    </p>
                  </div>

                  <button type="button" className="event-modal-close" onClick={closeLogDetails} aria-label="Close details">
                    <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 5l10 10M15 5L5 15" /></svg>
                    <span>Close details</span>
                  </button>
                </div>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(2, 1fr)",
                    gap: "14px 30px",
                  }}
                >
                  <div>
                    <strong>Timestamp</strong>
                    <p>{formatTimestampIST(selectedLog.timestamp_ist || selectedLog.timestamp)}</p>
                  </div>

                  <div>
                    <strong>Source IP</strong>
                    <p>{selectedLog.src_ip || "-"}</p>
                  </div>

                  <div>
                    <strong>Source Port</strong>
                    <p>{selectedLog.src_port || "-"}</p>
                  </div>

                  <div>
                    <strong>Destination Port</strong>
                    <p>
                      {selectedLog.destination_port || "-"}
                    </p>
                  </div>

                  <div>
                    <strong>Session ID</strong>
                    <p>{selectedLog.session_id || "-"}</p>
                  </div>

                  <div>
                    <strong>Event ID</strong>
                    <p>{selectedLog.event_id || "-"}</p>
                  </div>

                  <div>
                    <strong>Username</strong>
                    <p>{selectedLog.username || "-"}</p>
                  </div>

                  <div>
                    <strong>Credential</strong>
                    <p>********</p>
                  </div>

                  <div>
                    <strong>Attack Type</strong>
                    <p>{selectedLog.attack_type || "-"}</p>
                  </div>

                  <div>
                    <strong>Risk Level</strong>
                    <p>{selectedLog.risk_level || "-"}</p>
                  </div>

                  <div>
                    <strong>Risk Score</strong>
                    <p>{selectedLog.risk_score ?? "-"}</p>
                  </div>

                  <div>
                    <strong>Recommended Action</strong>
                    <p>
                      {getSystemResponse(selectedLog)}
                    </p>
                  </div>

                  {String(
                    selectedLog.calculated_risk_level || selectedLog.risk_level || ""
                  ).toLowerCase() === "critical" && (
                    <div>
                      <strong>IP Response</strong>
                      <div style={{ marginTop: "8px" }}>
                        <button
                          type="button"
                          onClick={() => handleBlockIp(selectedLog.src_ip)}
                          disabled={!selectedLog.src_ip || blockingIp === selectedLog.src_ip}
                          style={{
                            border: "1px solid #9f3f3f",
                            borderRadius: "4px",
                            padding: "8px 14px",
                            background: blockingIp === selectedLog.src_ip ? "#f3f4f6" : "#fff7f6",
                            color: "#9f3f3f",
                            cursor: selectedLog.src_ip && blockingIp !== selectedLog.src_ip ? "pointer" : "not-allowed",
                            fontSize: "13px",
                            fontWeight: 600,
                          }}
                        >
                          {blockingIp === selectedLog.src_ip ? "Blocking..." : "Block IP"}
                        </button>
                        {blockMessage && (
                          <p style={{ margin: "8px 0 0", fontSize: "12px", color: "#667085" }}>
                            {blockMessage}
                          </p>
                        )}
                      </div>
                    </div>
                  )}

                  <div style={{ gridColumn: "1 / -1" }}>
                    <strong>Command</strong>
                    <p>
                      {selectedLog.command_input ||
                        "No command recorded"}
                    </p>
                  </div>

                  <div style={{ gridColumn: "1 / -1" }}>
                    <strong>Explanation</strong>
                    <p>
                      {selectedLog.explanation ||
                        "No explanation available."}
                    </p>
                  </div>

                  <div style={{ gridColumn: "1 / -1" }}>
                    <strong>Data Origin</strong>
                    <p>
                      {selectedLog.data_origin ||
                        "Cowrie dataset"}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {/* ================================================= */}
        {/* ================= ATTACK LOGS ==================== */}
        {/* ================================================= */}

        {activePage === "Attack Logs" && (
          <>
            <div className="page-header">
              <h1>Attack Logs</h1>

              <p>
                Detailed view of suspicious interactions collected by Cowrie.
              </p>
            </div>

            <div className="logs-page-panel">

              <div className="logs-page-tools">

                <input
                  type="text"
                  placeholder="Search attack logs..."
                  value={searchText}
                  onChange={(event) =>
                    setSearchText(event.target.value)
                  }
                />

                <select
                  value={selectedRisk}
                  onChange={(event) =>
                    setSelectedRisk(event.target.value)
                  }
                >
                  <option value="All">All Risks</option>
                  <option value="Low">Low</option>
                  <option value="Medium">Medium</option>
                  <option value="High">High</option>
                  <option value="Critical">Critical</option>
                </select>

              </div>

              {loading ? (
                <div className="no-results">
                  Loading Cowrie data...
                </div>
              ) : (
                <div className="full-logs-table">

                  <div className="table-header">
                    <span>Timestamp</span>
                    <span>Source IP</span>
                    <span>Attack Type</span>
                    <span>Risk</span>
                    <span>Score</span>
                  </div>

                  {filteredLogs.map((log, index) => (
                    <div
                      className="table-row"
                      key={`${log.session_id}-${index}`}
                      onClick={() => openLogDetails(log)}
                      style={{ cursor: "pointer" }}
                    >
                      <span>{formatTimestampIST(log.timestamp_ist || log.timestamp)}</span>

                      <span>{log.src_ip || "-"}</span>

                      <span>{log.attack_type || "-"}</span>

                      <span
                        className={String(
                          log.risk_level || ""
                        ).toLowerCase()}
                      >
                        {log.risk_level || "-"}
                      </span>

                      <span>{log.risk_score ?? "-"}</span>
                    </div>
                  ))}

                  {filteredLogs.length === 0 && (
                    <div className="no-results">
                      No matching attack logs found.
                    </div>
                  )}

                </div>
              )}

              {selectedLog && (
                <div
                  className="panel event-detail-modal" role="dialog" aria-modal="true" aria-label="Event details"
                  style={{
                    marginTop: "20px",
                    border: "1px solid #d9dde3",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: "20px",
                    }}
                  >
                    <div>
                      <h3>Attack Log Details</h3>

                      <p className="panel-description">
                        Detailed information for the selected Cowrie event.
                      </p>
                    </div>

                    <button type="button" className="event-modal-close" onClick={closeLogDetails} aria-label="Close details">
                      <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 5l10 10M15 5L5 15" /></svg>
                      <span>Close details</span>
                    </button>
                  </div>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(2, 1fr)",
                      gap: "14px 30px",
                    }}
                  >
                    <div>
                      <strong>Timestamp</strong>
                      <p>{formatTimestampIST(selectedLog.timestamp_ist || selectedLog.timestamp)}</p>
                    </div>

                    <div>
                      <strong>Source IP</strong>
                      <p>{selectedLog.src_ip || "-"}</p>
                    </div>

                    <div>
                      <strong>Source Port</strong>
                      <p>{selectedLog.src_port || "-"}</p>
                    </div>

                    <div>
                      <strong>Destination Port</strong>
                      <p>
                        {selectedLog.destination_port || "-"}
                      </p>
                    </div>

                    <div>
                      <strong>Session ID</strong>
                      <p>{selectedLog.session_id || "-"}</p>
                    </div>

                    <div>
                      <strong>Event ID</strong>
                      <p>{selectedLog.event_id || "-"}</p>
                    </div>

                    <div>
                      <strong>Username</strong>
                      <p>{selectedLog.username || "-"}</p>
                    </div>

                    <div>
                      <strong>Credential</strong>
                      <p>********</p>
                    </div>

                    <div>
                      <strong>Attack Type</strong>
                      <p>{selectedLog.attack_type || "-"}</p>
                    </div>

                    <div>
                      <strong>Risk Level</strong>
                      <p>{selectedLog.risk_level || "-"}</p>
                    </div>

                    <div>
                      <strong>Risk Score</strong>
                      <p>{selectedLog.risk_score ?? "-"}</p>
                    </div>

                    <div>
                      <strong>Recommended Action</strong>
                      <p>
                        {getSystemResponse(selectedLog)}
                      </p>
                    </div>

                    <div style={{ gridColumn: "1 / -1" }}>
                      <strong>Command</strong>
                      <p>
                        {selectedLog.command_input ||
                          "No command recorded"}
                      </p>
                    </div>

                    <div style={{ gridColumn: "1 / -1" }}>
                      <strong>Explanation</strong>
                      <p>
                        {selectedLog.explanation ||
                          "No explanation available."}
                      </p>
                    </div>

                    <div style={{ gridColumn: "1 / -1" }}>
                      <strong>Data Origin</strong>
                      <p>
                        {selectedLog.data_origin ||
                          "Cowrie dataset"}
                      </p>
                    </div>
                  </div>
                </div>
              )}

            </div>
          </>
        )}

        {/* ================================================= */}
        {/* ================= RISK ANALYSIS ================== */}
        {/* ================================================= */}

        {activePage === "Risk Analysis" && (
          <>
            <div className="page-header">

              <h1>Risk Analysis</h1>

              <p>
                Explainable risk assessment based on observable Cowrie events.
              </p>

            </div>

            <div className="risk-page-layout">

              {/* DATASET RISK DISTRIBUTION */}

              <div className="panel risk-distribution">

                <h3>Dataset Risk Distribution</h3>

                <p className="panel-description">
                  Risk labels present in the complete Cowrie dataset.
                </p>

                <div className="risk-bar-row">

                  <span>Critical</span>

                  <div className="risk-bar">

                    <div
                      className="risk-bar-fill high-fill"
                      style={{
                        width:
                          totalEvents > 0
                            ? `${criticalPercentage}%`
                            : "0%",
                      }}
                    />

                  </div>

                  <strong>
                    {loading
                      ? "..."
                      : `${criticalRisk} (${criticalPercentage}%)`}
                  </strong>

                </div>

                <div className="risk-bar-row">

                  <span>High</span>

                  <div className="risk-bar">

                    <div
                      className="risk-bar-fill high-fill"
                      style={{
                        width:
                          totalEvents > 0
                            ? `${highPercentage}%`
                            : "0%",
                      }}
                    />

                  </div>

                  <strong>
                    {loading
                      ? "..."
                      : `${highRisk} (${highPercentage}%)`}
                  </strong>

                </div>

                <div className="risk-bar-row">

                  <span>Medium</span>

                  <div className="risk-bar">

                    <div
                      className="risk-bar-fill medium-fill"
                      style={{
                        width:
                          totalEvents > 0
                            ? `${mediumPercentage}%`
                            : "0%",
                      }}
                    />

                  </div>

                  <strong>
                    {loading
                      ? "..."
                      : `${mediumRisk} (${mediumPercentage}%)`}
                  </strong>

                </div>

                <div className="risk-bar-row">

                  <span>Low</span>

                  <div className="risk-bar">

                    <div
                      className="risk-bar-fill low-fill"
                      style={{
                        width:
                          totalEvents > 0
                            ? `${lowPercentage}%`
                            : "0%",
                      }}
                    />

                  </div>

                  <strong>
                    {loading
                      ? "..."
                      : `${lowRisk} (${lowPercentage}%)`}
                  </strong>

                </div>

                <div
                  style={{
                    marginTop: "24px",
                    paddingTop: "16px",
                    borderTop: "1px solid #e1e4e8",
                  }}
                >
                  <strong>
                    Total Events: {loading ? "..." : totalEvents}
                  </strong>
                </div>

              </div>

              {/* EXPLAINABLE RISK ENGINE */}

              <div className="panel">

                <h3>Explainable Risk Assessment</h3>

                <p className="panel-description">
                  Rule-based risk calculation applied to the first 100
                  dataset records.
                </p>

                {riskLoading ? (
                  <div className="no-results">
                    Loading risk analysis...
                  </div>
                ) : (
                  <>
                    <div className="risk-rules">

                      <div className="rule-row">
                        <strong>Low</strong>
                        <span>
                          0–24 — Continue monitoring
                        </span>
                      </div>

                      <div className="rule-row">
                        <strong>Medium</strong>
                        <span>
                          25–49 — Continue monitoring
                        </span>
                      </div>

                      <div className="rule-row">
                        <strong>High</strong>
                        <span>
                          50–74 — Notified by email
                        </span>
                      </div>

                      <div className="rule-row">
                        <strong>Critical</strong>
                        <span>
                          75–100 — Email notification + manual IP blocking option
                        </span>
                      </div>

                    </div>

                    <div
                      style={{
                        marginTop: "20px",
                        paddingTop: "16px",
                        borderTop: "1px solid #e1e4e8",
                      }}
                    >
                      <strong>
                        Analysed Records: {riskAnalysis.length}
                      </strong>
                    </div>

                  </>
                )}

              </div>

              {/* CALCULATED RISK SUMMARY */}

              <div className="panel">

                <h3>Calculated Risk Summary</h3>

                <p className="panel-description">
                  Risk levels calculated using the explainable rule-based
                  assessment.
                </p>

                <div
                  className="summary-cards"
                  style={{
                    marginTop: "18px",
                    display: "grid",
                    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                    gap: "16px",
                    width: "100%",
                    minWidth: 0,
                  }}
                >

                  <div
                    className="summary-card"
                    style={{
                      minWidth: 0,
                      width: "100%",
                      boxSizing: "border-box",
                      overflow: "hidden",
                    }}
                  >
                    <p>Low Risk</p>
                    <h2>{riskLoading ? "..." : calculatedLow}</h2>
                    <span>{calculatedLowPercentage}% of analysed records</span>
                  </div>

                  <div
                    className="summary-card"
                    style={{
                      minWidth: 0,
                      width: "100%",
                      boxSizing: "border-box",
                      overflow: "hidden",
                    }}
                  >
                    <p>Medium Risk</p>
                    <h2>{riskLoading ? "..." : calculatedMedium}</h2>
                    <span>{calculatedMediumPercentage}% of analysed records</span>
                  </div>

                  <div
                    className="summary-card"
                    style={{
                      minWidth: 0,
                      width: "100%",
                      boxSizing: "border-box",
                      overflow: "hidden",
                    }}
                  >
                    <p>High Risk</p>
                    <h2>{riskLoading ? "..." : calculatedHigh}</h2>
                    <span>{calculatedHighPercentage}% of analysed records</span>
                  </div>

                  <div
                    className="summary-card"
                    style={{
                      minWidth: 0,
                      width: "100%",
                      boxSizing: "border-box",
                      overflow: "hidden",
                    }}
                  >
                    <p>Critical Risk</p>
                    <h2>{riskLoading ? "..." : calculatedCritical}</h2>
                    <span>{calculatedCriticalPercentage}% of analysed records</span>
                  </div>

                </div>

              </div>

              {/* CALCULATED RISK BAR CHART */}

              <div className="panel">

                <h3>Calculated Risk Distribution</h3>

                <p className="panel-description">
                  Visual distribution of the explainable risk levels in the
                  analysed records.
                </p>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(4, 1fr)",
                    gap: "18px",
                    alignItems: "end",
                    minHeight: "230px",
                    marginTop: "24px",
                    padding: "0 10px",
                  }}
                >

                  {calculatedRiskBars.map((bar) => (
                    <div
                      key={bar.label}
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                        justifyContent: "flex-end",
                        height: "200px",
                      }}
                    >
                      <strong style={{ marginBottom: "8px" }}>
                        {riskLoading ? "..." : bar.count}
                      </strong>

                      <div
                        style={{
                          width: "54px",
                          height: `${
                            calculatedTotal > 0
                              ? Math.max(
                                  (bar.count / calculatedTotal) * 140,
                                  bar.count > 0 ? 10 : 2
                                )
                              : 2
                          }px`,
                          minHeight: bar.count > 0 ? "10px" : "2px",
                          background:
                            bar.label === "Low"
                              ? "#6f8f72"
                              : bar.label === "Medium"
                              ? "#b59a5b"
                              : bar.label === "High"
                              ? "#b86b61"
                              : "#8f4d4d",
                          borderRadius: "4px 4px 0 0",
                        }}
                      />

                      <span
                        style={{
                          marginTop: "8px",
                          fontSize: "13px",
                          fontWeight: "600",
                        }}
                      >
                        {bar.label}
                      </span>

                      <span
                        style={{
                          marginTop: "3px",
                          fontSize: "11px",
                          color: "#6b7280",
                        }}
                      >
                        {bar.percentage}%
                      </span>
                    </div>
                  ))}

                </div>

              </div>

              {/* RISK INTERPRETATION */}

              <div className="panel">

                <h3>Risk Interpretation</h3>

                <p className="panel-description">
                  Risk classification helps prioritize suspicious events
                  for further analysis.
                </p>

                <div className="risk-rules">

                  <div className="rule-row">
                    <strong>Total Dataset Events</strong>
                    <span>
                      {loading ? "..." : totalEvents}
                    </span>
                  </div>

                  <div className="rule-row">
                    <strong>Attack Events</strong>
                    <span>
                      {loading ? "..." : attackEvents}
                    </span>
                  </div>

                  <div className="rule-row">
                    <strong>Higher Risk Dataset Events</strong>
                    <span>
                      {loading
                        ? "..."
                        : highRisk + criticalRisk}
                    </span>
                  </div>

                  <div className="rule-row">
                    <strong>Rule-Based Assessment</strong>
                    <span>
                      Explainable
                    </span>
                  </div>

                </div>

              </div>

            </div>

            {/* EXPLAINABLE EVENT TABLE */}

            <div
              className="panel"
              style={{
                marginTop: "20px",
              }}
            >

              <h3>Explainable Event Assessment</h3>

              <p className="panel-description">
                Select an event to view the factors used to calculate its
                risk score.
              </p>

              {riskLoading ? (
                <div className="no-results">
                  Loading risk assessment...
                </div>
              ) : (
                <div className="full-logs-table">

                  <div className="table-header">
                    <span>Event</span>
                    <span>Attack Type</span>
                    <span>Risk Score</span>
                    <span>Risk Level</span>
                    <span>Action</span>
                  </div>

                  {riskAnalysis.slice(0, 10).map((log, index) => (
                    <div
                      className="table-row"
                      key={`${log.session_id}-${log.record_number}-${index}`}
                      onClick={() => openRiskDetails(log)}
                      style={{ cursor: "pointer" }}
                    >
                      <span>
                        {log.event_id || "-"}
                      </span>

                      <span>
                        {log.attack_type || "-"}
                      </span>

                      <span>
                        {log.calculated_risk_score ?? "-"}
                      </span>

                      <span
                        className={String(
                          log.calculated_risk_level || ""
                        ).toLowerCase()}
                      >
                        {log.calculated_risk_level || "-"}
                      </span>

                      <span>
                        {getSystemResponse(log)}
                      </span>
                    </div>
                  ))}

                </div>
              )}

            </div>

            {/* SELECTED RISK EVENT */}

            {selectedRiskEvent && (
              <div
                className="panel event-detail-modal event-risk-modal" role="dialog" aria-modal="true" aria-label="Risk assessment and SHAP details"
                style={{
                  marginTop: "20px",
                  border: "1px solid #d9dde3",
                }}
              >

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "20px",
                  }}
                >

                  <div>
                    <h3>Risk Assessment Details</h3>

                    <p className="panel-description">
                      Explanation of how the selected event was assessed.
                    </p>
                  </div>

                  <button type="button" className="event-modal-close" onClick={closeRiskDetails} aria-label="Close details">
                    <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 5l10 10M15 5L5 15" /></svg>
                    <span>Close details</span>
                  </button>

                </div>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(2, 1fr)",
                    gap: "14px 30px",
                  }}
                >

                  <div>
                    <strong>Event ID</strong>
                    <p>
                      {selectedRiskEvent.event_id || "-"}
                    </p>
                  </div>

                  <div>
                    <strong>Timestamp</strong>
                    <p>
                      {formatTimestampIST(selectedRiskEvent.timestamp_ist || selectedRiskEvent.timestamp)}
                    </p>
                  </div>

                  <div>
                    <strong>Source IP</strong>
                    <p>
                      {selectedRiskEvent.src_ip || "-"}
                    </p>
                  </div>

                  <div>
                    <strong>Attack Type</strong>
                    <p>
                      {selectedRiskEvent.attack_type || "-"}
                    </p>
                  </div>

                  <div>
                    <strong>Recorded Risk Level</strong>
                    <p>
                      {selectedRiskEvent.risk_level || "-"}
                    </p>
                  </div>

                  <div>
                    <strong>Calculated Risk</strong>
                    <p>
                      {selectedRiskEvent.calculated_risk_level || "-"}
                    </p>
                  </div>

                  <div>
                    <strong>Calculated Risk Score</strong>
                    <p>
                      {selectedRiskEvent.calculated_risk_score ?? "-"} / 100
                    </p>
                  </div>

                  <div>
                    <strong>Recommended Action</strong>
                    <p>
                      {getSystemResponse(selectedRiskEvent)}
                    </p>
                  </div>

                  {String(selectedRiskEvent.calculated_risk_level || "").toLowerCase() === "critical" && (
                    <div>
                      <strong>IP Response</strong>
                      <div style={{ marginTop: "8px" }}>
                        <button
                          type="button"
                          onClick={() => handleBlockIp(selectedRiskEvent.src_ip)}
                          disabled={!selectedRiskEvent.src_ip || blockingIp === selectedRiskEvent.src_ip}
                          style={{
                            border: "1px solid #9f3f3f",
                            borderRadius: "4px",
                            padding: "8px 14px",
                            background: blockingIp === selectedRiskEvent.src_ip ? "#f3f4f6" : "#fff7f6",
                            color: "#9f3f3f",
                            cursor: selectedRiskEvent.src_ip && blockingIp !== selectedRiskEvent.src_ip ? "pointer" : "not-allowed",
                            fontSize: "13px",
                            fontWeight: 600,
                          }}
                        >
                          {blockingIp === selectedRiskEvent.src_ip ? "Blocking..." : "Block IP"}
                        </button>
                        {blockMessage && (
                          <p style={{ margin: "8px 0 0", fontSize: "12px", color: "#667085" }}>
                            {blockMessage}
                          </p>
                        )}
                      </div>
                    </div>
                  )}

                  <div style={{ gridColumn: "1 / -1" }}>
                    <strong>Command</strong>
                    <p>
                      {selectedRiskEvent.command_input ||
                        "No command recorded"}
                    </p>
                  </div>

                  <div style={{ gridColumn: "1 / -1" }}>
                    <strong>Risk Reasons</strong>

                    {selectedRiskEvent.risk_reasons &&
                    selectedRiskEvent.risk_reasons.length > 0 ? (
                      <ul>
                        {selectedRiskEvent.risk_reasons.map(
                          (reason, index) => (
                            <li key={index}>
                              {reason}
                            </li>
                          )
                        )}
                      </ul>
                    ) : (
                      <p>No specific risk reason recorded.</p>
                    )}

                  </div>

                  <div style={{ gridColumn: "1 / -1" }}>
                    <strong>Explanation</strong>
                    <p>
                      {selectedRiskEvent.explanation ||
                        "No explanation available."}
                    </p>
                  </div>

                  <div style={{ gridColumn: "1 / -1" }}>
                    <strong>Data Origin</strong>
                    <p>
                      {selectedRiskEvent.data_origin ||
                        "Cowrie dataset"}
                    </p>
                  </div>

                </div>

                {/* ================= SHAP EXPLANATION ================= */}

                <div
                  style={{
                    marginTop: "24px",
                    paddingTop: "20px",
                    borderTop: "1px solid #e1e4e8",
                  }}
                >
                  <h3 style={{ marginTop: 0, marginBottom: "6px" }}>
                    Explainable AI — SHAP Analysis
                  </h3>

                  <p className="panel-description">
                    SHAP TreeExplainer shows how individual features
                    contributed to the Random Forest risk prediction for this
                    event.
                  </p>

                  {shapLoading ? (
                    <div className="no-results" style={{ marginTop: "14px" }}>
                      Loading SHAP explanation...
                    </div>
                  ) : shapError ? (
                    <div
                      style={{
                        marginTop: "14px",
                        padding: "12px",
                        border: "1px solid #f1c0bc",
                        borderRadius: "5px",
                        background: "#fff7f6",
                        color: "#b42318",
                        fontSize: "13px",
                      }}
                    >
                      {shapError}
                    </div>
                  ) : shapExplanation ? (
                    <>
                      <div
                        className="risk-rules"
                        style={{ marginTop: "14px" }}
                      >
                        <div className="rule-row">
                          <strong>Model</strong>
                          <span>
                            {shapExplanation.model_type ||
                              "Random Forest"}
                          </span>
                        </div>

                        <div className="rule-row">
                          <strong>Explanation Method</strong>
                          <span>
                            {shapExplanation.explanation_method ||
                              "SHAP TreeExplainer"}
                          </span>
                        </div>

                        <div className="rule-row">
                          <strong>Predicted Risk</strong>
                          <span>
                            {shapExplanation.predicted_risk_level ||
                              shapExplanation.predicted_class ||
                              "-"}
                          </span>
                        </div>

                        <div className="rule-row">
                          <strong>Actual Risk Level</strong>
                          <span>
                            {shapExplanation.actual_risk_level ||
                              selectedRiskEvent.risk_level ||
                              "-"}
                          </span>
                        </div>
                      </div>

                      <div style={{ marginTop: "18px" }}>
                        <strong>Feature Contributions</strong>

                        {Array.isArray(shapExplanation.shap_values) &&
                        shapExplanation.shap_values.length > 0 ? (
                          <div
                            className="full-logs-table"
                            style={{ marginTop: "10px" }}
                          >
                            <div className="table-header">
                              <span>Feature</span>
                              <span>Value</span>
                              <span>SHAP Value</span>
                              <span>Effect</span>
                            </div>

                            {shapExplanation.shap_values
                              .slice()
                              .sort(
                                (a, b) =>
                                  Math.abs(Number(b.shap_value) || 0) -
                                  Math.abs(Number(a.shap_value) || 0)
                              )
                              .map((item, index) => (
                                <div
                                  className="table-row"
                                  key={`${item.feature || "feature"}-${index}`}
                                >
                                  <span>
                                    {item.feature || "-"}
                                  </span>
                                  <span>
                                    {item.value ?? "-"}
                                  </span>
                                  <span>
                                    {Number(item.shap_value || 0).toFixed(6)}
                                  </span>
                                  <span>
                                    {item.effect || "-"}
                                  </span>
                                </div>
                              ))}
                          </div>
                        ) : (
                          <div
                            className="no-results"
                            style={{ marginTop: "10px" }}
                          >
                            No SHAP feature contributions were returned.
                          </div>
                        )}
                      </div>

                      <p
                        style={{
                          marginTop: "14px",
                          marginBottom: 0,
                          color: "#667085",
                          fontSize: "12px",
                          lineHeight: 1.5,
                        }}
                      >
                        Positive SHAP values indicate features that increased
                        the model's predicted risk, while negative values
                        indicate features that decreased it for this event.
                      </p>
                    </>
                  ) : (
                    <div
                      className="no-results"
                      style={{ marginTop: "14px" }}
                    >
                      Select an event to generate its SHAP explanation.
                    </div>
                  )}
                </div>

              </div>
            )}

          </>
        )}

        {/* ================================================= */}
        {/* =============== DATASET ANALYSIS ================= */}
        {/* ================================================= */}

        {activePage === "Dataset Analysis" && (
          <>
            <div className="page-header">
              <h1>Dataset Analysis</h1>
              <p>
                Upload a CSV file to calculate rule-based risk scores and review
                the results without changing stored Cowrie events.
              </p>
            </div>

            <div className="panel dataset-upload-panel">
              <h3>Upload CSV Dataset</h3>
              <p className="panel-description">
                Supported size: up to 5 MB and 5,000 records. Include at least
                one analysis column: event_id, event_type, command_input,
                command, or input.
              </p>

              <form onSubmit={handleDatasetAnalysis} className="dataset-upload-form">
                <div className="dataset-file-control">
                  <label htmlFor="dataset-csv-file">CSV file</label>
                  <input
                    id="dataset-csv-file"
                    type="file"
                    accept=".csv,text/csv"
                    onChange={(event) => {
                      setDatasetFile(event.target.files?.[0] || null);
                      setDatasetError("");
                      setDatasetSuccess("");
                    }}
                    disabled={datasetLoading}
                  />
                  <span className="dataset-file-hint">
                    {datasetFile
                      ? `${datasetFile.name} (${(datasetFile.size / 1024).toFixed(1)} KB)`
                      : "Choose a .csv file from your computer"}
                  </span>
                </div>

                <div className="dataset-upload-actions">
                  <button type="submit" className="dataset-primary-button" disabled={datasetLoading || !datasetFile}>
                    {datasetLoading ? "Analysing CSV..." : "Analyse Dataset"}
                  </button>
                  <button type="button" className="dataset-secondary-button" onClick={clearDatasetAnalysis} disabled={datasetLoading}>
                    Clear Results
                  </button>
                </div>
              </form>

              {datasetError && (
                <div className="dataset-message dataset-message-error" role="alert">
                  {datasetError}
                </div>
              )}
              {datasetSuccess && (
                <div className="dataset-message dataset-message-success" role="status">
                  {datasetSuccess}
                </div>
              )}
              <p className="dataset-privacy-note">
                Uploaded records are analysed in memory only. They are not saved
                to the training dataset or live-event database, and this upload
                does not trigger email notifications.
              </p>
            </div>

            {datasetAnalysis && (
              <>
                <div className="dataset-result-heading">
                  <div>
                    <h2>Analysis Results</h2>
                    <p>
                      {datasetAnalysis.total_records} records analysed using the
                      existing rule-based assessment. This is not a Random Forest
                      or SHAP prediction.
                    </p>
                  </div>
                  <span className="dataset-method-label">Rule-based analysis</span>
                </div>

                <div className="dataset-summary-grid">
                  <div className="summary-card dataset-risk-low">
                    <p>Low Risk</p>
                    <h2>{datasetAnalysis.risk_summary?.low ?? 0}</h2>
                    <span>Score 0–24</span>
                  </div>
                  <div className="summary-card dataset-risk-medium">
                    <p>Medium Risk</p>
                    <h2>{datasetAnalysis.risk_summary?.medium ?? 0}</h2>
                    <span>Score 25–49</span>
                  </div>
                  <div className="summary-card dataset-risk-high">
                    <p>High Risk</p>
                    <h2>{datasetAnalysis.risk_summary?.high ?? 0}</h2>
                    <span>Score 50–74</span>
                  </div>
                  <div className="summary-card dataset-risk-critical">
                    <p>Critical Risk</p>
                    <h2>{datasetAnalysis.risk_summary?.critical ?? 0}</h2>
                    <span>Score 75–100</span>
                  </div>
                </div>

                <div className="panel dataset-results-panel">
                  <div className="dataset-results-toolbar">
                    <div>
                      <h3>Analysed Records</h3>
                      <p className="panel-description">
                        Showing {filteredDatasetRecords.length} of {uploadedDatasetRecords.length} records.
                      </p>
                    </div>
                    <div className="dataset-filter-controls">
                      <input
                        type="search"
                        aria-label="Search analysed records"
                        placeholder="Search IP, event, command..."
                        value={datasetSearch}
                        onChange={(event) => setDatasetSearch(event.target.value)}
                      />
                      <select
                        aria-label="Filter by risk level"
                        value={datasetRiskFilter}
                        onChange={(event) => setDatasetRiskFilter(event.target.value)}
                      >
                        <option value="All">All Risks</option>
                        <option value="Low">Low</option>
                        <option value="Medium">Medium</option>
                        <option value="High">High</option>
                        <option value="Critical">Critical</option>
                      </select>
                    </div>
                  </div>

                  <div className="dataset-table-wrap">
                    <table className="dataset-results-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Timestamp</th>
                          <th>Source IP</th>
                          <th>Event</th>
                          <th>Command / Input</th>
                          <th>Risk Score</th>
                          <th>Risk Level</th>
                          <th>Reason / Explanation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredDatasetRecords.map((record, index) => {
                          const riskLevel = String(record.calculated_risk_level || "Low");
                          const riskReasons = Array.isArray(record.risk_reasons)
                            ? record.risk_reasons.join("; ")
                            : record.explanation || "No major suspicious indicator detected";
                          return (
                            <tr key={`${record.dataset_index ?? index}-${index}`}>
                              <td>{Number(record.dataset_index ?? index) + 1}</td>
                              <td>{formatTimestampIST(record.timestamp || record.time || record.datetime)}</td>
                              <td>{record.src_ip || record.source_ip || "-"}</td>
                              <td>{record.event_id || record.event_type || record.attack_type || "-"}</td>
                              <td className="dataset-command-cell">{record.command_input || record.command || record.input || "-"}</td>
                              <td>{record.calculated_risk_score ?? "-"}</td>
                              <td>
                                <span className={`dataset-risk-pill ${riskLevel.toLowerCase()}`}>
                                  {riskLevel}
                                </span>
                              </td>
                              <td className="dataset-reason-cell">{riskReasons}</td>
                            </tr>
                          );
                        })}
                        {filteredDatasetRecords.length === 0 && (
                          <tr>
                            <td colSpan="8" className="dataset-empty-cell">
                              No records match the selected search and risk filter.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
          </>
        )}

        {/* ================================================= */}
        {/* ===================== ALERTS ===================== */}
        {/* ================================================= */}

        {activePage === "Alerts" && (
          <>
            <div className="page-header">
              <h1>Alerts</h1>

              <p>
                Alert-worthy events received from the Cowrie backend alert
                endpoint.
              </p>
            </div>

            {alertsLoading ? (
              <div className="no-results">
                Loading backend alerts...
              </div>
            ) : (
              <>
                {/* ================= ALERT SUMMARY ================= */}

                <div
                  className="alert-summary-grid"
                  style={{
                    display: "grid",
                    gridTemplateColumns:
                      "repeat(3, minmax(0, 1fr))",
                    gap: "16px",
                    marginBottom: "20px",
                  }}
                >
                  <div
                    className="panel"
                    style={{
                      margin: 0,
                      minWidth: 0,
                      boxSizing: "border-box",
                    }}
                  >
                    <span
                      style={{
                        display: "block",
                        color: "#667085",
                        fontSize: "14px",
                        marginBottom: "8px",
                      }}
                    >
                      Critical Alerts
                    </span>

                    <strong
                      style={{
                        display: "block",
                        fontSize: "28px",
                        color: "#9f3f3f",
                      }}
                    >
                      {backendCriticalAlerts.length}
                    </strong>

                    <p
                      style={{
                        margin: "6px 0 0",
                        color: "#667085",
                        fontSize: "13px",
                      }}
                    >
                      Email notification + analyst-reviewed manual IP blocking
                    </p>
                  </div>

                  <div
                    className="panel"
                    style={{
                      margin: 0,
                      minWidth: 0,
                      boxSizing: "border-box",
                    }}
                  >
                    <span
                      style={{
                        display: "block",
                        color: "#667085",
                        fontSize: "14px",
                        marginBottom: "8px",
                      }}
                    >
                      High-Risk System Notifications
                    </span>

                    <strong
                      style={{
                        display: "block",
                        fontSize: "28px",
                        color: "#a66a00",
                      }}
                    >
                      {backendHighAlerts.length}
                    </strong>

                    <p
                      style={{
                        margin: "6px 0 0",
                        color: "#667085",
                        fontSize: "13px",
                      }}
                    >
                      Email notifications to verified users who opted in
                    </p>
                  </div>

                  <div
                    className="panel"
                    style={{
                      margin: 0,
                      minWidth: 0,
                      boxSizing: "border-box",
                    }}
                  >
                    <span
                      style={{
                        display: "block",
                        color: "#667085",
                        fontSize: "14px",
                        marginBottom: "8px",
                      }}
                    >
                      Total Alert-Worthy Events
                    </span>

                    <strong
                      style={{
                        display: "block",
                        fontSize: "28px",
                        color: "#253b63",
                      }}
                    >
                      {backendAlertCount}
                    </strong>

                    <p
                      style={{
                        margin: "6px 0 0",
                        color: "#667085",
                        fontSize: "13px",
                      }}
                    >
                      High and critical events returned by backend
                    </p>
                  </div>
                </div>

                {/* ================= ALERT LIST ================= */}

                <div
                  className="alert-list"
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "14px",
                  }}
                >
                  {alerts.length === 0 ? (
                    <div className="panel">
                      No high or critical alerts were returned by the
                      backend.
                    </div>
                  ) : (
                    alerts.map((log, index) => {
                      const level =
                        log.calculated_risk_level ||
                        log.risk_level ||
                        log.level ||
                        "High";

                      const isCritical =
                        String(level).toLowerCase() === "critical";

                      return (
                        <div
                          className="alert-card"
                          key={`${log.session_id || log.event_id || "alert"}-${index}`}
                          onClick={() => openLogDetails(log)}
                          style={{
                            cursor: "pointer",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "flex-start",
                            gap: "20px",
                            minWidth: 0,
                            boxSizing: "border-box",
                          }}
                        >
                          <div style={{ minWidth: 0 }}>
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "10px",
                                marginBottom: "8px",
                              }}
                            >
                              <h3 style={{ margin: 0 }}>
                                {log.event_id || "Security Event"}
                              </h3>

                              <span
                                className="alert-badge"
                                style={{
                                  background: isCritical
                                    ? "#f4dddd"
                                    : "#f8ebc8",
                                  color: isCritical
                                    ? "#8f3737"
                                    : "#8a5a00",
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {level}
                              </span>
                            </div>

                            <p style={{ margin: "0 0 8px" }}>
                              {log.explanation ||
                                log.reason ||
                                "Alert generated by the backend risk assessment."}
                            </p>

                            <div
                              style={{
                                display: "flex",
                                flexWrap: "wrap",
                                gap: "14px",
                                color: "#667085",
                                fontSize: "13px",
                              }}
                            >
                              <span>
                                Score:{" "}
                                <strong>
                                  {log.calculated_risk_score ??
                                    log.risk_score ??
                                    "-"}
                                </strong>
                              </span>

                              <span>
                                Source IP:{" "}
                                <strong>{log.src_ip || "-"}</strong>
                              </span>

                              <span>
                                Event:{" "}
                                <strong>{log.attack_type || "-"}</strong>
                              </span>
                            </div>
                          </div>

                          <div
                            style={{
                              minWidth: "170px",
                              textAlign: "right",
                              color: "#667085",
                              fontSize: "13px",
                            }}
                          >
                            <div>{formatTimestampIST(log.timestamp_ist || log.timestamp)}</div>

                            <div
                              style={{
                                marginTop: "8px",
                                color: isCritical ? "#8f3737" : "#a66a00",
                                fontWeight: 600,
                              }}
                            >
                              {getSystemResponse(log)}
                            </div>
                            <button
                              type="button"
                              className="block-ip-button"
                              disabled={!log.src_ip || Boolean(blockingIp)}
                              onClick={(event) => {
                                event.stopPropagation();
                                handleBlockIp(log.src_ip);
                              }}
                            >
                              {blockingIp === log.src_ip ? "Blocking..." : "Block IP"}
                            </button>
                            {blockMessage && blockingIp === "" && (
                              <div className="block-ip-message" role="status">
                                {blockMessage}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                {/* ================= SELECTED ALERT DETAILS ================= */}

                {selectedLog && (
                  <div
                    className="panel event-detail-modal" role="dialog" aria-modal="true" aria-label="Event details"
                    style={{
                      marginTop: "20px",
                      minWidth: 0,
                      boxSizing: "border-box",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: "12px",
                        marginBottom: "18px",
                      }}
                    >
                      <div>
                        <h3 style={{ margin: 0 }}>
                          Alert Event Details
                        </h3>

                        <p
                          style={{
                            margin: "5px 0 0",
                            color: "#667085",
                            fontSize: "13px",
                          }}
                        >
                          Explainable assessment for the selected event.
                        </p>
                      </div>

                      <button type="button" className="event-modal-close" onClick={closeLogDetails} aria-label="Close details">
                        <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 5l10 10M15 5L5 15" /></svg>
                        <span>Close details</span>
                      </button>
                    </div>

                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns:
                          "repeat(2, minmax(0, 1fr))",
                        gap: "16px",
                      }}
                    >
                      <div>
                        <strong>Event ID</strong>
                        <p>{selectedLog.event_id || "-"}</p>
                      </div>

                      <div>
                        <strong>Calculated Risk Level</strong>
                        <p>
                          {selectedLog.calculated_risk_level ||
                            selectedLog.risk_level ||
                            "-"}
                        </p>
                      </div>

                      <div>
                        <strong>Calculated Risk Score</strong>
                        <p>
                          {selectedLog.calculated_risk_score ??
                            selectedLog.risk_score ??
                            "-"}
                        </p>
                      </div>

                      <div>
                        <strong>Recommended Action</strong>
                        <p>
                          {getSystemResponse(selectedLog)}
                        </p>
                      </div>

                      <div>
                        <strong>Source IP</strong>
                        <p>{selectedLog.src_ip || "-"}</p>
                      </div>

                      <div>
                        <strong>Destination Port</strong>
                        <p>
                          {selectedLog.destination_port || "-"}
                        </p>
                      </div>

                      <div>
                        <strong>Username</strong>
                        <p>{selectedLog.username || "-"}</p>
                      </div>

                      <div>
                        <strong>Timestamp</strong>
                        <p>{formatTimestampIST(selectedLog.timestamp_ist || selectedLog.timestamp)}</p>
                      </div>

                      <div style={{ gridColumn: "1 / -1" }}>
                        <strong>Reason</strong>
                        <p>
                          {selectedLog.reason ||
                            selectedLog.explanation ||
                            "No explanation available."}
                        </p>
                      </div>

                      <div style={{ gridColumn: "1 / -1" }}>
                        <strong>Command</strong>
                        <p>
                          {selectedLog.command_input ||
                            selectedLog.input ||
                            "No command recorded"}
                        </p>
                      </div>

                      <div style={{ gridColumn: "1 / -1" }}>
                        <strong>Data Origin</strong>
                        <p>
                          {selectedLog.data_origin ||
                            "Cowrie dataset"}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* ================= BACKEND ALERT STATUS ================= */}

                <div
                  className="panel"
                  style={{
                    marginTop: "20px",
                    minWidth: 0,
                    boxSizing: "border-box",
                  }}
                >
                  <h3 style={{ marginTop: 0 }}>
                    Backend Alert Status
                  </h3>

                  <div
                    className="risk-rules"
                    style={{ marginTop: "12px" }}
                  >
                    <div className="rule-row">
                      <strong>Backend Endpoint</strong>
                      <span>/api/alerts</span>
                    </div>

                    <div className="rule-row">
                      <strong>Alerts Returned</strong>
                      <span>{alertMeta?.count ?? alerts.length}</span>
                    </div>

                    <div className="rule-row">
                      <strong>Email Notifications Sent</strong>
                      <span>
                        {alertMeta?.email_notifications_sent ?? 0}
                      </span>
                    </div>

                    <div className="rule-row">
                      <strong>Notification Request</strong>
                      <span>
                        {alertMeta?.notification_requested
                          ? "Requested"
                          : "Not requested"}
                      </span>
                    </div>
                  </div>

                  <p
                    style={{
                      color: "#667085",
                      marginBottom: 0,
                      marginTop: "14px",
                    }}
                  >
                    The Alerts page reads alert records from the Flask backend. High and Critical events trigger email notifications for verified users who enabled notifications. IP blocking is a separate analyst-initiated action through the dashboard.
                  </p>
                </div>
              </>
            )}
          </>
        )}

      </main>
    </div>
  );
}

export default App;