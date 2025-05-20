document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('register-form');
    const errorMessage = document.getElementById('error-message');

    form.addEventListener('submit', async (e) => {
        e.preventDefault(); // Prevent default form submission

        const formData = new FormData(form);
        try {
            const response = await fetch('/register', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                window.location.href = '/login'; // Redirect to login on success
            } else {
                const errorText = await response.text();
                errorMessage.textContent = errorText;
                errorMessage.style.display = 'block';
            }
        } catch (err) {
            errorMessage.textContent = 'Error submitting form: ' + err.message;
            errorMessage.style.display = 'block';
        }
    });
});
