document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, fetching product...');
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
        addItem(pid, quantity = 1) {
            pid = pid.toString();
            if (this.items.has(pid)) {
                const item = this.items.get(pid);
                item.setQuantity(item.quantity + parseInt(quantity));
            } else {
                this.items.set(pid, new CartItem(pid, quantity));
                this.fetchProductDetails(pid);
            }
            this.saveToLocalStorage();
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
            const fetchPromises = cartData.map(data => {
                const item = new CartItem(data.pid, data.quantity);
                this.items.set(data.pid, item);
                return this.fetchProductDetails(data.pid);
            });
            Promise.all(fetchPromises).then(() => this.render());
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

    
    // Get product pid from URL query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('pid');
    console.log('Product ID from URL:', productId);

    fetch(`http://${ipaddr}:3000/api/product/${productId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(product => {
            console.log('Product received:', product);

            // Update hierarchical nav
            const hierarchicalNav = document.querySelector('.hierarchical-nav');
            if (hierarchicalNav) {
                let categoryLink = '';
                switch (product.catid) {
                    case 1:
                        categoryLink = `<a href="./category.html?catid=${product.catid}">Chinese Books</a>`;
                        break;
                    case 2:
                        categoryLink = `<a href="./category.html?catid=${product.catid}">English Books</a>`;
                        break;
                    case 3:
                        categoryLink = `<a href="./category.html?catid=${product.catid}">Magazines</a>`;
                        break;
                    default:
                        categoryLink = '<a href="#">Unknown Category</a>';
                }
                hierarchicalNav.innerHTML = `
                    <a href="./index.html">Home</a> \> 
                    ${categoryLink} \> 
                    ${product.name}
                `;
            }

            // Update product container
            const productContainer = document.querySelector('.product-container');
            if (productContainer) {
                productContainer.innerHTML = `
                    <img src="http://${ipaddr}:3000${product.image}" alt="${product.name}">
                    <div class="product-description">
                        <h2>${product.name}</h2>
                        <h5>Author: ${product.author || 'Unknown'} <br> Publisher: ${product.publisher|| 'Unknown'} </h5>
                        <p>${product.description || 'No description available'}</p>
                    </div>
                    <div class="purchase">
                        <h3>${product.name}</h3>
                        Price: $${product.price.toFixed(2)}
                        <div class="quantity-select">
                            <label for="quantity">Select Quantity:</label>
                            <select id="quantity">
                                <option value="1">1</option>
                                <option value="2">2</option>
                                <option value="3">3</option>
                                <option value="4">4</option>
                                <option value="5">5</option>
                            </select>
                        </div>
                        <button class = "add-to-cart" data-pid="${product.pid}">Add to cart</button>
                    </div>
                `;
                // Add event listener for "Add to cart" button
                document.querySelector('.add-to-cart').addEventListener('click', () => {

                    
                    const quantity = Number(document.getElementById('quantity').value);
                    const pid = product.pid.toString();

                    cart.addItem(pid, quantity);
                });
            
            }
        })
        .catch(error => console.error('Error fetching product:', error));

    // Event delegation for cart interactions(+,-,remove)
    const shoppingList = document.querySelector('.shopping-list');
    if (shoppingList) {
        shoppingList.addEventListener('click', (e) => {
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

        shoppingList.addEventListener('input', (e) => {
            if (e.target.classList.contains('quantity')) {
                const pid = e.target.dataset.pid;
                const quantity = e.target.value;
                cart.updateQuantity(pid, quantity);
            }
        });
    }

    // Initial render of cart
    cart.render();
});