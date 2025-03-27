// Анимация элементов при загрузке страницы
document.addEventListener("DOMContentLoaded", () => {
  console.log("SecureLink initialized");
  const elements = document.querySelectorAll(".card, .feature");
  elements.forEach((el, index) => {
    el.style.opacity = "0";
    el.style.transform = "translateY(20px)";
    el.style.animation = `fadeIn 0.5s ease forwards ${index * 0.1}s`;
  });
});

// Анимация кнопки при нажатии
const scanButton = document.querySelector(".scan-button");
if (scanButton) {
  scanButton.addEventListener("click", function () {
    this.classList.add("scanning");
    setTimeout(() => {
      this.classList.remove("scanning");
    }, 2000);
  });
}
