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
    const resetButton = document.getElementById('reset-password-button');
    const loginButton = document.getElementById('login-button');
    const registerButton = document.getElementById('register-button');

    if (logoutButtonMain) {
        logoutButtonMain.addEventListener('click', logout);
    }

    if (resetButton) {
        resetButton.addEventListener('click', () => {
            window.location.href = '/change-password';
        });
    }

    if (loginButton) {
        loginButton.addEventListener('click', () => {
            window.location.href = '/login?view=login';
        });
    }

    if (registerButton) {
        registerButton.addEventListener('click', () => {
            window.location.href = '/register';
        });
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

    //Handle form in password recovery page
    const recoverForm = document.getElementById('recover-password-form');
    const errorMessage = document.getElementById('recover-error-message');
    const successMessage = document.getElementById('recover-success-message');

    if (recoverForm) {
        recoverForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = new FormData(recoverForm);

            try {
                const response = await fetch('/recover-password', {
                    method: 'POST',
                    body: formData,
                    credentials: 'include'
                });

                const data = await response.json();
                if (!response.ok) {
                    errorMessage.style.display = 'block';
                    errorMessage.textContent = data.message || 'Failed to request password reset';
                    successMessage.style.display = 'none';
                    return;
                }

                successMessage.style.display = 'block';
                successMessage.textContent = data.message;
                errorMessage.style.display = 'none';

                // Optionally disable the form after success
                recoverForm.querySelector('button').disabled = true;
                recoverForm.querySelector('input[type="email"]').disabled = true;
            } catch (err) {
                errorMessage.style.display = 'block';
                errorMessage.textContent = 'Error: Unable to connect to the server';
                successMessage.style.display = 'none';
                console.error('Recover password error:', err);
            }
        });
    }


    // Handle password reset form submission (on /reset-password/:nonce page)
    const resetPasswordForm = document.getElementById('reset-password-form');
    if (resetPasswordForm) {
        const resetErrorMessage = document.getElementById('reset-error-message');

        resetPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const formData = new FormData(resetPasswordForm);

            // Client-side validation
            if (newPassword !== confirmPassword) {
                resetErrorMessage.style.display = 'block';
                resetErrorMessage.textContent = 'New password and confirmation do not match';
                return;
            }

            if (newPassword.length < 8) {
                resetErrorMessage.style.display = 'block';
                resetErrorMessage.textContent = 'New password must be at least 8 characters long';
                return;
            }

            try {
                const response = await fetch(resetPasswordForm.action, {
                    method: 'POST',
                    body: formData,
                    credentials: 'include'
                });

                const data = await response.json();
                if (!response.ok) {
                    resetErrorMessage.style.display = 'block';
                    resetErrorMessage.textContent = data.message || 'Failed to reset password';
                    return;
                }

                alert(data.message);
                window.location.href = '/login';
            } catch (err) {
                resetErrorMessage.style.display = 'block';
                resetErrorMessage.textContent = 'Error: Unable to connect to the server';
                console.error('Reset password error:', err);
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