document.addEventListener("DOMContentLoaded", function () {
    setTimeout(function () {
        let alertBox = document.querySelector('.alert');
        if (alertBox) {
            alertBox.style.transition = "opacity 0.5s ease";
            alertBox.style.opacity = "0";
            setTimeout(() => alertBox.remove(), 500); // Удаление из DOM
        }
    }, 3000);
});