document.addEventListener("DOMContentLoaded", function () {
    var widget = document.getElementById("altcha-widget");
    var progressFill = document.getElementById("progress-fill");
    var statusText = document.getElementById("challenge-status");
    var challengeIcon = document.getElementById("challenge-icon");

    if (!widget) return;

    var fakeProgress = 0;
    var progressInterval = setInterval(function () {
        fakeProgress = Math.min(fakeProgress + Math.random() * 2.5, 88);
        progressFill.style.width = fakeProgress + "%";
    }, 150);

    widget.addEventListener("statechange", function (ev) {
        if (ev.detail.state === "verified") {
            clearInterval(progressInterval);
            progressFill.style.width = "100%";
            progressFill.classList.add("progress-done");
            challengeIcon.textContent = "✓";
            challengeIcon.classList.add("challenge-icon-done");
            statusText.textContent = "Verification complete. Redirecting...";
            document.getElementById("altcha-payload").value = ev.detail.payload;
            setTimeout(function () {
                document.getElementById("challenge-form").submit();
            }, 500);
        } else if (ev.detail.state === "error") {
            clearInterval(progressInterval);
            challengeIcon.textContent = "✕";
            challengeIcon.classList.add("challenge-icon-error");
            statusText.textContent = "Verification failed. Please reload the page.";
            progressFill.classList.add("progress-error");
        }
    });
});
