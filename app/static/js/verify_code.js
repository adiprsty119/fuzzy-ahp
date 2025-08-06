// Mengambil waktu kedaluwarsa dari elemen HTML
const expiryTime = parseInt(
  document.getElementById("expiry-time").dataset.expiry,
  10
);
const countdownElement = document.getElementById("countdown");

// Fungsi untuk memulai hitung mundur
function startCountdown() {
  const interval = setInterval(() => {
    const now = Math.floor(new Date().getTime() / 1000);
    const remainingTime = expiryTime - now;

    if (remainingTime <= 0) {
      clearInterval(interval);
      countdownElement.textContent = "The code has expired.";
      countdownElement.style.color = "red";
    } else {
      const minutes = Math.floor(remainingTime / 60);
      const seconds = remainingTime % 60;
      countdownElement.textContent = `Code remaining period ${minutes}:${seconds
        .toString()
        .padStart(2, "0")}`;
    }
  }, 1000);
}

document.addEventListener("DOMContentLoaded", () => {
  startCountdown();

  document
    .getElementById("verify-btn")
    .addEventListener("click", async (event) => {
      event.preventDefault(); // Prevent default form submission

      const code = document.querySelector(
        "input[name='verification_code']"
      ).value;

      try {
        const response = await fetch("/verify_code/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ verification_code: code }),
        });

        const result = await response.json();
        console.log("Fetch result:", result);

        if (response.ok) {
          alert(result.message); // Menampilkan pesan sukses
          if (result.redirect_url) {
            window.location.href = result.redirect_url; // Mengarahkan user ke halaman reset_password
          } else {
            console.error("Redirect URL not found in response.");
          }
        } else {
          const error = await response.json();
          alert(error.message);
        }
      } catch (error) {
        console.error("Error during verification:", error);
      }
    });
});
