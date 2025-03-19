document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorMessage = document.getElementById('error-message');

    const ipaddr = 's13.ierg4210.ie.cuhk.edu.hk';
    try {
        const response = await fetch(`https://${ipaddr}:3000/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });

        const data = await response.json();
        if (!response.ok) {
            errorMessage.style.display = 'block';
            errorMessage.textContent = data.message || 'Login failed';
            return;
        }

        // Store username in localStorage
        localStorage.setItem('username', data.username);

        // Redirect based on user role
        if (data.is_admin) {
            window.location.href = '/admin';
        } else {
            window.location.href = '/index.html';
        }
    } catch (err) {
        errorMessage.style.display = 'block';
        errorMessage.textContent = 'Error: Unable to connect to the server';
    }
});