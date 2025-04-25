// CartItem class (copied from index.js for consistency)
class CartItem {
    constructor(pid, quantity = 1, name = '', price = 0) {
        if (!validateInteger(pid)) throw new Error('Invalid pid');
        this.pid = pid;
        this.quantity = Math.max(1, parseInt(quantity, 10)); // Ensure >= 1
        this.name = escapeHtml(name); // Sanitize on init
        this.price = parseFloat(price) || 0;
    }

    getSubtotal() {
        return (this.price * this.quantity).toFixed(2);
    }

    setQuantity(quantity) {
        this.quantity = Math.max(1, parseInt(quantity, 10) || 1);
    }
}

// Helper function to validate integers (copied from index.js)
function validateInteger(value) {
    return Number.isInteger(parseInt(value)) && parseInt(value) >= 0;
}

// Helper function to escape HTML (copied from index.js)
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

document.addEventListener('DOMContentLoaded', async () => {
    const checkoutItemsContainer = document.getElementById('checkout-items');
    const errorMessageContainer = document.getElementById('error-message');
    const placeOrderForm = document.getElementById('place-order-form');
    const checkoutForm = document.getElementById('checkout-form');

    const stripe = Stripe('pk_test_51RCagsFRiY6DBE1yfawKN6lY2zPI8gX2FtWyWM39zBR223eeDDrFzSxtWTezPFfp28xtVjBm01ECZSgtU7V43dsh00k1U8qxfs');

    // Step 1: Load cart data from localStorage (same format as index.js)
    const cartData = JSON.parse(localStorage.getItem('shoppingCart') || '[]');
    if (cartData.length === 0) {
        checkoutItemsContainer.innerHTML = '<p>Your cart is empty.</p>';
        placeOrderForm.style.display = 'none'; // Hide the form
        return;
    }

    // Step 2: Create CartItem instances and fetch product details
    const cartItems = new Map();
    const fetchPromises = cartData.map(async (data) => {
        try {
            const response = await fetch(`/api/product/${encodeURIComponent(data.pid)}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });
            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            const product = await response.json();

            const item = {
                pid: data.pid,
                quantity: data.quantity,
                name: escapeHtml(product.name),
                price: parseFloat(product.price) || 0,
                image: product.image,
                getSubtotal: function () {
                    return (this.price * this.quantity).toFixed(2);
                }
            };
            cartItems.set(data.pid, item);
        } catch (error) {
            console.error(`Error fetching product ${data.pid}:`, error);
            cartItems.delete(data.pid);
        }
    });

    await Promise.all(fetchPromises);

    // Render the cart items
    checkoutItemsContainer.innerHTML = Array.from(cartItems.values()).map(item => `
        <div class="checkout-item">
            <img src="${escapeHtml(item.image || '/default-image.jpg')}" alt="${escapeHtml(item.name || 'Unknown Product')}" onerror="this.src='/default-image.jpg';">
            <p>Name: ${escapeHtml(item.name || 'Unknown Product')}</p>
            <p>Price: $${escapeHtml(item.price.toFixed(2))}</p>
            <p>Quantity: ${escapeHtml(String(item.quantity))}</p>
            <p>Subtotal: $${escapeHtml(item.getSubtotal())}</p>
        </div>
    `).join('');

    // Calculate and display the total
    const total = Array.from(cartItems.values())
        .reduce((sum, item) => sum + parseFloat(item.getSubtotal()), 0)
        .toFixed(2);
    checkoutItemsContainer.innerHTML += `<p><strong>Total: $${total}</strong></p>`;

    // Handle form submission to initiate Stripe Checkout
    checkoutForm.addEventListener('submit', async (event) => {
        event.preventDefault(); // Prevent default form submission

        const placeOrderBtn = document.getElementById('place-order-btn');
        placeOrderBtn.disabled = true; // Disable button to prevent multiple submissions

        const csrfToken = checkoutForm.querySelector('input[name="_csrf"]').value;
        if (!csrfToken) {
            errorMessageContainer.textContent = 'CSRF token not found. Please refresh the page and try again.';
            placeOrderBtn.disabled = false;
            return;
        }

        try {
            // Send cart data to the server to create a Stripe Checkout session
            const response = await fetch('/create-checkout-session', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'CSRF-Token': csrfToken
                },
                body: JSON.stringify({ cart: cartData }),
                credentials: 'include'
            });
            

            const session = await response.json();
            console.log('Session response:', session);

            if (session.error) {
                throw new Error(session.error);
            }

            if (!session.id || typeof session.id !== 'string' || !session.id.startsWith('cs_')) {
                throw new Error('Invalid session ID received from server');
            }

            // Add hidden fields for orderID and digest
            const orderIDInput = document.createElement('input');
            orderIDInput.type = 'hidden';
            orderIDInput.name = 'invoice';
            orderIDInput.value = session.orderID;
            checkoutForm.appendChild(orderIDInput);

            const digestInput = document.createElement('input');
            digestInput.type = 'hidden';
            digestInput.name = 'custom';
            digestInput.value = session.digest;
            checkoutForm.appendChild(digestInput);

            localStorage.removeItem('shoppingCart');

            // Redirect to Stripe Checkout
            const result = await stripe.redirectToCheckout({
                sessionId: session.id
            });

            if (result.error) {
                throw new Error(result.error.message);
            }
        } catch (error) {
            console.error('Error initiating Stripe Checkout:', error);
            errorMessageContainer.textContent = error.message || 'Failed to initiate checkout. Please try again.';
            placeOrderBtn.disabled = false; // Re-enable button on error
        }
    });
});
