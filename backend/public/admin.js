document.addEventListener('DOMContentLoaded', () => {
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', logout);
    }
});

function logout() {
    const csrfToken = document.querySelector('input[name="_csrf"]').value;
    fetch('/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ _csrf: csrfToken })
    })
    .then(response => response.json())
    .then(data => {
        localStorage.removeItem('username');
        alert(data.message);
        window.location.href = '/login';
    })
    .catch(err => {
        console.error('Logout error:', err);
        alert('Logout failed');
    });
}

function validateForm(form) {
    const inputs = form.querySelectorAll('input, textarea, select');
    for (let input of inputs) {
        if (input.name === 'name' || input.name === 'author' || input.name === 'publisher') {
            if (!input.value || input.value.length > 255 || /[<>&"']/.test(input.value)) {
                alert('Text fields must be non-empty, max 255 chars, no HTML');
                return false;
            }
        }
        if (input.name === 'price') {
            const val = parseFloat(input.value);
            if (isNaN(val) || val < 0 || val > 10000) {
                alert('Price must be a number between 0 and 10000');
                return false;
            }
        }
        if (input.name === 'description' && input.value.length > 1000) {
            alert('Description max 1000 chars');
            return false;
        }
        if (input.name === 'catid' && !/^\d+$/.test(input.value)) {
            alert('Category must be a valid ID');
            return false;
        }
    }
    return true;
}