const resetPasswordForm = document.getElementById("resetPasswordForm");
const newPasswordInput = document.getElementById("newPassword");
const confirmPasswordInput = document.getElementById("confirmPassword");
const strengthIndicator = document.getElementById("strengthIndicator");
const errorMessage = document.getElementById("errorMessage");

// Ambil token dari URL
const token = new URLSearchParams(window.location.search).get("token");

if (!token) {
  strengthIndicator.textContent = "Token tidak valid atau hilang.";
  strengthIndicator.style.color = "red";

  // Nonaktifkan formulir
  resetPasswordForm.style.display = "none";
} else {
  strengthIndicator.textContent = "Silakan masukkan password baru.";
  strengthIndicator.style.color = "black";
}

// Validasi kekuatan password secara real-time
newPasswordInput.addEventListener("input", () => {
  const value = newPasswordInput.value;
  let strength = "Weak";

  if (
    value.length >= 8 &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[@$!%*?&]/.test(value)
  ) {
    strength = "Strong";
  } else if (value.length >= 6) {
    strength = "Medium";
  }

  strengthIndicator.textContent = `${strength} password`;
  strengthIndicator.style.color =
    strength === "Strong" ? "green" : strength === "Medium" ? "orange" : "red";
});

// Tangani pengiriman formulir
resetPasswordForm.addEventListener("submit", async (e) => {
  e.preventDefault(); // Mencegah pengiriman formulir default

  const newPassword = newPasswordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  if (newPassword !== confirmPassword) {
    alert("Password dan konfirmasi password tidak cocok.");
    return;
  }

  try {
    const response = await fetch("/reset_password/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        reset_token: token,
        new_password: newPassword,
        confirm_password: confirmPassword,
      }),
    });

    const result = await response.json();

    if (response.ok) {
      alert(result.message);
      window.location.href = "/login/";
    } else {
      alert(result.error || "Terjadi kesalahan.");
    }
  } catch (error) {
    console.error("Error:", error);
    alert("Terjadi kesalahan jaringan. Silakan coba lagi.");
  }
});

// Error Message
if (!token) {
  errorMessage.textContent = "Link reset tidak valid atau sudah kedaluwarsa.";
  errorMessage.style.display = "block";
  resetPasswordForm.style.display = "none";
}
