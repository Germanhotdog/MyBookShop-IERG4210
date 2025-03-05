document.addEventListener('DOMContentLoaded', () => {
    const ipaddr = 'localhost'; 

    // CartItem class to represent a single item in the cart
    class CartItem {
        constructor(pid, quantity = 1, name = '', price = 0) {
            this.pid = pid;
            this.quantity = quantity;
            this.name = name;
            this.price = price;
        }

        // Calculate subtotal for this item
        getSubtotal() {
            return this.price * this.quantity;
        }

        // Update quantity
        setQuantity(quantity) {
            this.quantity = Math.max(1, parseInt(quantity)); // Ensure quantity >= 1
        }
    }

    // Cart class to manage the shopping cart
    class Cart {
        constructor() {
            this.items = new Map(); // Map of pid -> CartItem
            this.loadFromLocalStorage(); // Load initial state
        }

        // Add or update item in cart
        addItem(pid) {
            if (this.items.has(pid)) {
                const item = this.items.get(pid);
                item.setQuantity(item.quantity + 1); // Increment if exists
            } else {
                this.items.set(pid, new CartItem(pid));
                this.fetchProductDetails(pid); // Fetch details for new item
            }
            this.saveToLocalStorage();
            this.render();
        }

        // Fetch product details via AJAX
        fetchProductDetails(pid) {
            fetch(`http://${ipaddr}:3000/api/product/${pid}`)
                .then(response => {
                    if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
                    return response.json();
                })
                .then(product => {
                    const item = this.items.get(pid);
                    item.name = product.name;
                    item.price = parseFloat(product.price);
                    this.saveToLocalStorage();
                    this.render();
                })
                .catch(error => console.error(`Error fetching product ${pid}:`, error));
        }

        // Update quantity for an item
        updateQuantity(pid, quantity) {
            const item = this.items.get(pid);
            if (item) {
                item.setQuantity(quantity);
                this.saveToLocalStorage();
                this.render();
            }
        }

        // Remove item from cart
        removeItem(pid) {
            this.items.delete(pid);
            this.saveToLocalStorage();
            this.render();
        }

        // Calculate total amount
        getTotal() {
            let total = 0;
            for (const item of this.items.values()) {
                total += item.getSubtotal();
            }
            return total.toFixed(2);
        }

        // Save to localStorage
        saveToLocalStorage() {
            const cartData = Array.from(this.items.entries()).map(([pid, item]) => ({
                pid: item.pid,
                quantity: item.quantity
            }));
            localStorage.setItem('shoppingCart', JSON.stringify(cartData));
        }

        // Load from localStorage
        loadFromLocalStorage() {
            const cartData = JSON.parse(localStorage.getItem('shoppingCart') || '[]');
            cartData.forEach(data => {
                const item = new CartItem(data.pid, data.quantity);
                this.items.set(data.pid, item);
                this.fetchProductDetails(data.pid); // Fetch details for each restored item
            });
        }

        // Render cart to DOM
        render() {
            const cartItems = document.getElementById('cart-items');
            const cartTotal = document.getElementById('cart-total');
            if (!cartItems || !cartTotal) return;

            cartItems.innerHTML = Array.from(this.items.values()).map(item => `
                <li data-pid="${item.pid}">
                    ${item.name || 'Loading...'} <br>
                    Quantity: 
                    <button class="decrement" data-pid="${item.pid}">-</button>
                    <input type="number" class="quantity" data-pid="${item.pid}" value="${item.quantity}" min="1">
                    <button class="increment" data-pid="${item.pid}">+</button> <br>
                    - $${item.getSubtotal().toFixed(2)}
                    <button class="remove" data-pid="${item.pid}">Remove</button>
                </li>
            `).join('');
            cartTotal.textContent = `Total: $${this.getTotal()}`;
        }
    }

    // Initialize cart
    const cart = new Cart();

    // Get catid from URL query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const catid = urlParams.get('catid');
    if (!catid) {
        console.error('No category ID found in URL');
        return;
    }

    // Fetch category details
    fetch(`http://${ipaddr}:3000/api/categories/${catid}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(category => {
            document.getElementById('category-name').textContent = category.name;
            document.getElementById('category-title').textContent = `${category.name}`;
        })
        .catch(error => console.error('Error fetching category:', error));

    // Fetch and render products for this category
    fetch(`http://${ipaddr}:3000/api/products?catid=${catid}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(products => {
            const container = document.getElementById('flex-container');
            container.innerHTML = products.map(product => `
                <div>
                    <a href="./product.html?pid=${product.pid}">
                        <img src="http://${ipaddr}:3000${product.image}" alt="${product.name}">
                        <p>${product.name}</p>
                        <p style="font-size:10px">Author: ${product.author || 'Unknown'} <br> Publisher: ${product.publisher || 'Unknown'}</p>
                    </a>
                    <div class="PriceButton-container">
                        <p>$${product.price.toFixed(2)}</p>
                        <button class="add-to-cart" data-pid="${product.pid}">Add to cart</button>
                    </div>
                </div>
            `).join('');

            // Add event listeners for "Add to cart" buttons
            document.querySelectorAll('.add-to-cart').forEach(button => {
                button.addEventListener('click', (e) => {
                    const pid = e.target.dataset.pid;
                    cart.addItem(pid);
                });
            });
        })
        .catch(error => console.error('Error fetching products:', error));

    // Fetch and render categories for side navigation
    fetch(`http://${ipaddr}:3000/api/categories`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(categories => {
            const categoryContainer = document.getElementById('side-nav-list');
            categoryContainer.innerHTML = categories.map(category => `
                <a href="category.html?catid=${category.catid}">
                    <li>${category.name}</li>
                </a>
            `).join('');
        })
        .catch(error => console.error('Error fetching categories:', error));

    // Event delegation for cart interactions(+,-,remove)
    document.addEventListener('click', (e) => {
        const pid = e.target.dataset.pid;
        if (!pid) return;

        if (e.target.classList.contains('increment')) {
            const item = cart.items.get(pid);
            cart.updateQuantity(pid, item.quantity + 1);
        } else if (e.target.classList.contains('decrement')) {
            const item = cart.items.get(pid);
            cart.updateQuantity(pid, item.quantity - 1);
        } else if (e.target.classList.contains('remove')) {
            cart.removeItem(pid);
        }
    });

    document.addEventListener('input', (e) => {
        if (e.target.classList.contains('quantity')) {
            const pid = e.target.dataset.pid;
            const quantity = e.target.value;
            cart.updateQuantity(pid, quantity);
        }
    });

    // Initial render of cart
    cart.render();
});