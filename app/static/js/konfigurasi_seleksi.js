async function saveConfig() {
  const comp = document.getElementById("configComponent");
  if (!comp) {
    console.error("configComponent not found");
    return;
  }
  const state = Alpine.$data(comp);
  const bodyState = Alpine.$data(document.body);

  // ✅ validasi semua activities + criteria di dalamnya
  for (let act of state.activities || []) {
    if (!act.nama || !act.mulai || !act.selesai) {
      bodyState.modal = {
        show: true,
        title: "Peringatan",
        message: "Nama kegiatan dan periode wajib diisi",
      };
      return;
    }

    for (let c of act.criteria || []) {
      if (!c.nama) {
        bodyState.modal = {
          show: true,
          title: "Peringatan",
          message: "Semua kriteria wajib diisi namanya",
        };
        return;
      }
      if (!c.skala || c.skala < 1 || c.skala > 10) {
        bodyState.modal = {
          show: true,
          title: "Peringatan",
          message: "Skala kriteria harus bernilai 1–10",
        };
        return;
      }
      if (
        c.jenis === undefined ||
        c.jenis === null ||
        (Array.isArray(c.jenis) && c.jenis.length === 0) ||
        (typeof c.jenis === "string" && c.jenis.trim() === "")
      ) {
        bodyState.modal = {
          show: true,
          title: "Peringatan",
          message: "Jenis penilaian wajib diatur",
        };
        return;
      }
    }
  }

  // payload cukup activities saja
  const payload = {
    activities: state.activities,
  };

  // CSRF token
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
      setTimeout(() => {
        bodyState.page = "main";
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
    bodyState.modal = {
      show: true,
      title: "Error",
      message: err.message || "Terjadi kesalahan pada server.",
    };
  }
}

// Function Save Periode
function savePeriode() {
  const comp = document.getElementById("configComponent");
  if (!comp) return;
  const state = Alpine.$data(comp);
  const invalidAct = state.activities.find(
    (a) => !a.nama || !a.mulai || !a.selesai
  );
  if (invalidAct) {
    state.errorMessage = "Nama kegiatan dan periode harus diisi";
    return;
  }

  // ✅ Sinkronisasi array contingents agar sama panjang dengan activities
  if (state.contingents.length !== state.activities.length) {
    state.contingents = state.activities.map((act, i) => {
      return (
        state.contingents[i] || {
          nama: act.nama,
          umpiPutra: 0,
          umpiPutri: 0,
        }
      );
    });
  }

  // set completed & tab
  state.completed.periode = true;
  state.tab = "kuota";
  state.errorMessage = "";
}

// Function Push Kriteria Default
function getDefaultCriteria() {
  return [
    { nama: "Status Keaktifan di Gugus Depan", skala: 1, jenis: "Kualitatif" },
    { nama: "Pencapaian SKU", skala: 1, jenis: "Kualitatif" },
    { nama: "Pencapaian SPG", skala: 1, jenis: "Kualitatif" },
    { nama: "Kesehatan Jasmani dan Rohani", skala: 1, jenis: "Kualitatif" },
    { nama: "Tes Wawancara", skala: 1, jenis: [] }, // multi-aspek
    {
      nama: "Tes Pilihan Ganda",
      skala: 1,
      jenis: "Kuantitatif",
      jumlahSoal: 0,
    },
  ];
}
