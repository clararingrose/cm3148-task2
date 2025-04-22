function showPassword(elementId) {
    var passwordField = document.getElementById(elementId);
    if (passwordField.type === "password") {
        passwordField.type = "text";
    } else {
        passwordField.type = "password";
    }
}

function hidePassword(elementId) {
    var passwordField = document.getElementById(elementId);
    if (passwordField.type === "text") {
        passwordField.type = "password";
    } else {
        passwordField.type = "text";
    }
}