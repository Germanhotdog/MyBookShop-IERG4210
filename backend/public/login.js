document.addEventListener('DOMContentLoaded', () => {
    // Handle login form submission (on /login page)
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        const loginErrorMessage = document.getElementById('error-message');
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const csrfToken = document.querySelector('input[name="_csrf"]').value;

            console.log('Sending login request:', { email, password });

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password, _csrf: csrfToken }),
                    credentials: 'include'
                });

                const data = await response.json();
                if (!response.ok) {
                    loginErrorMessage.style.display = 'block';
                    loginErrorMessage.textContent = data.message || 'Login failed';
                    return;
                }

                localStorage.setItem('username', data.username);
                if (data.is_admin) {
                    window.location.href = '/admin';
                } else {
                    window.location.href = '/';
                }
            } catch (err) {
                loginErrorMessage.style.display = 'block';
                loginErrorMessage.textContent = 'Error: Unable to connect to the server';
                console.error('Login error:', err);
            }
        });
    }

    // Handle logout button on the main content area of /login page
    const logoutButtonMain = document.getElementById('logout-button-main');
    if (logoutButtonMain) {
        logoutButtonMain.addEventListener('click', logout);
    }

    // Handle change password form submission (on /change-password page)
    const changePasswordForm = document.getElementById('change-password-form');
    if (changePasswordForm) {
        const changePasswordErrorMessage = document.getElementById('error-message');
        changePasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const currentPassword = document.getElementById('current-password').value;
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const csrfToken = document.querySelector('input[name="_csrf"]').value;

            // Client-side validation
            if (newPassword !== confirmPassword) {
                changePasswordErrorMessage.style.display = 'block';
                changePasswordErrorMessage.textContent = 'New password and confirmation do not match';
                return;
            }

            if (newPassword.length < 8) {
                changePasswordErrorMessage.style.display = 'block';
                changePasswordErrorMessage.textContent = 'New password must be at least 8 characters long';
                return;
            }

            try {
                const response = await fetch('/change-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        currentPassword,
                        newPassword,
                        confirmPassword,
                        _csrf: csrfToken
                    }),
                    credentials: 'include'
                });

                const data = await response.json();
                if (!response.ok) {
                    changePasswordErrorMessage.style.display = 'block';
                    changePasswordErrorMessage.textContent = data.message || 'Failed to change password';
                    return;
                }

                // On success, the server will destroy the session and redirect to /login
                localStorage.removeItem('username');
                alert(data.message);
                window.location.href = '/login';
            } catch (err) {
                changePasswordErrorMessage.style.display = 'block';
                changePasswordErrorMessage.textContent = 'Error: Unable to connect to the server';
                console.error('Change password error:', err);
            }
        });
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
        // Clear username from localStorage
        localStorage.removeItem('username');
        alert(data.message);
        window.location.href = '/login';
    })
    .catch(err => {
        console.error('Logout error:', err);
        alert('Logout failed');
    });
}