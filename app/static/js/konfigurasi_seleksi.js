// static/js/konfigurasi_seleksi.js
async function saveConfig() {
  const comp = document.getElementById("configComponent");
  if (!comp) {
    console.error("configComponent not found");
    return;
  }
  const state = Alpine.$data(comp);
  const bodyState = Alpine.$data(document.body);
  const total = (state.criteria || []).reduce(
    (sum, c) => sum + Number(c.bobot || 0),
    0
  );
  if (total !== 100) {
    bodyState.modal = {
      show: true,
      title: "Peringatan",
      message: "Total bobot harus 100%",
    };
    return;
  }

  // validasi nama activity
  if ((state.activities || []).some((a) => !a.nama || !a.mulai || !a.selesai)) {
    bodyState.modal = {
      show: true,
      title: "Peringatan",
      message: "Harap isi semua aktivitas",
    };
    return;
  }

  const payload = {
    activities: state.activities,
    criteria: state.criteria,
  };

  // ambil CSRF token
  const csrfTokenEl = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfTokenEl ? csrfTokenEl.content : "";

  try {
    const res = await fetch("/api/save_config", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken,
      },
      body: JSON.stringify(payload),
    });

    const text = await res.text();
    let result;
    try {
      result = JSON.parse(text);
    } catch (err) {
      throw new Error("Invalid JSON response: " + text);
    }

    if (result.status === "success") {
      bodyState.modal = {
        show: true,
        title: "Berhasil",
        message: result.message,
      };
      // optional redirect after delay
      setTimeout(() => {
        bodyState.page = "main";
        bodyState.$nextTick?.(() => {});
      }, 1000);
    } else {
      bodyState.modal = {
        show: true,
        title: "Error",
        message: result.message || "Terjadi kesalahan",
      };
    }
  } catch (err) {
    console.error("saveConfig error", err);
    const bodyState = Alpine.$data(document.body);
    bodyState.modal = {
      show: true,
      title: "Error",
      message: err.message || "Terjadi kesalahan pada server.",
    };
  }
}
