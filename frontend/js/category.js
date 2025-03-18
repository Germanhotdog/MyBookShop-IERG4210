// Escape HTML to prevent XSS
function escapeHtml(unsafe) {
    return String(unsafe)
      .replace(/&/g, "&")
      .replace(/</g, "<")
      .replace(/>/g, ">")
      .replace(/"/g, "\"")
      .replace(/'/g, "\'");
  }
  
  // Validate integer input (e.g., pid, catid, quantity)
  function validateInteger(value) {
    const num = parseInt(value, 10);
    return !isNaN(num) && num >= 0 && String(num) === String(value);
  }
  
  document.addEventListener('DOMContentLoaded', () => {
    // Use your domain for production; localhost for local testing
    const ipaddr = 's13.ierg4210.ie.cuhk.edu.hk'; // Update for EC2 deployment
  
    // CartItem class
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
  
    // Cart class
    class Cart {
      constructor() {
        this.items = new Map();
        this.loadFromLocalStorage();
      }
  
      addItem(pid) {
        if (!validateInteger(pid)) {
          console.error('Invalid pid:', pid);
          return;
        }
        if (this.items.has(pid)) {
          const item = this.items.get(pid);
          item.setQuantity(item.quantity + 1);
        } else {
          this.items.set(pid, new CartItem(pid));
          this.fetchProductDetails(pid);
        }
        this.saveToLocalStorage();
        this.render();
      }
  
      fetchProductDetails(pid) {
        fetch(`https://${ipaddr}:3000/api/product/${encodeURIComponent(pid)}`)
          .then(response => {
            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            return response.json();
          })
          .then(product => {
            const item = this.items.get(pid);
            if (item) {
              item.name = escapeHtml(product.name);
              item.price = parseFloat(product.price) || 0;
              this.saveToLocalStorage();
              this.render();
            }
          })
          .catch(error => console.error(`Error fetching product ${pid}:`, error));
      }
  
      updateQuantity(pid, quantity) {
        if (!validateInteger(pid) || !validateInteger(quantity)) return;
        const item = this.items.get(pid);
        if (item) {
          item.setQuantity(quantity);
          this.saveToLocalStorage();
          this.render();
        }
      }
  
      removeItem(pid) {
        if (!validateInteger(pid)) return;
        this.items.delete(pid);
        this.saveToLocalStorage();
        this.render();
      }
  
      getTotal() {
        let total = 0;
        for (const item of this.items.values()) {
          total += parseFloat(item.getSubtotal());
        }
        return total.toFixed(2);
      }
  
      saveToLocalStorage() {
        const cartData = Array.from(this.items.entries()).map(([pid, item]) => ({
          pid: item.pid,
          quantity: item.quantity
        }));
        localStorage.setItem('shoppingCart', JSON.stringify(cartData));
      }
  
      loadFromLocalStorage() {
        const cartData = JSON.parse(localStorage.getItem('shoppingCart') || '[]');
        cartData.forEach(data => {
          if (validateInteger(data.pid) && validateInteger(data.quantity)) {
            const item = new CartItem(data.pid, data.quantity);
            this.items.set(data.pid, item);
            this.fetchProductDetails(data.pid);
          }
        });
      }
  
      render() {
        const cartItems = document.getElementById('cart-items');
        const cartTotal = document.getElementById('cart-total');
        if (!cartItems || !cartTotal) return;
  
        cartItems.innerHTML = Array.from(this.items.values()).map(item => `
          <li data-pid="${escapeHtml(item.pid)}">
            ${escapeHtml(item.name || 'Loading...')} <br>
            Quantity:
            <button class="decrement" data-pid="${escapeHtml(item.pid)}">-</button>
            <input type="number" class="quantity" data-pid="${escapeHtml(item.pid)}" value="${escapeHtml(String(item.quantity))}" min="1" max="100" step="1">
            <button class="increment" data-pid="${escapeHtml(item.pid)}">+</button> <br>
            - $${escapeHtml(item.getSubtotal())}
            <button class="remove" data-pid="${escapeHtml(item.pid)}">Remove</button>
          </li>
        `).join('');
        cartTotal.textContent = escapeHtml(this.getTotal());
      }
    }
  
    const cart = new Cart();
  
    // Get catid from URL query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const catid = urlParams.get('catid');
    if (!validateInteger(catid)) {
      console.error('Invalid or missing category ID in URL');
      document.getElementById('category-title').textContent = 'Invalid Category';
      return;
    }
  
    // Fetch category details
    fetch(`https://${ipaddr}:3000/api/categories/${encodeURIComponent(catid)}`)
      .then(response => {
        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
        return response.json();
      })
      .then(category => {
        const safeName = escapeHtml(category.name);
        document.getElementById('category-name').textContent = safeName;
        document.getElementById('category-title').textContent = safeName;
      })
      .catch(error => {
        console.error('Error fetching category:', error);
        document.getElementById('category-title').textContent = 'Category Not Found';
      });
  
    // Fetch and render products for this category
    fetch(`https://${ipaddr}:3000/api/products?catid=${encodeURIComponent(catid)}`)
      .then(response => {
        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
        return response.json();
      })
      .then(products => {
        const container = document.getElementById('flex-container');
        if (!container) return;
        container.innerHTML = products.map(product => {
          if (!validateInteger(product.pid)) return '';
          return `
            <div>
              <a href="./product.html?pid=${encodeURIComponent(product.pid)}">
                <img src="https://${ipaddr}:3000${escapeHtml(product.image)}" alt="${escapeHtml(product.name)}">
                <p>${escapeHtml(product.name)}</p>
                <p style="font-size:10px">
                  Author: ${escapeHtml(product.author || 'Unknown')}<br>
                  Publisher: ${escapeHtml(product.publisher || 'Unknown')}
                </p>
              </a>
              <div class="PriceButton-container">
                <p>$${escapeHtml(String(product.price.toFixed(2)))}</p>
                <button class="add-to-cart" data-pid="${escapeHtml(String(product.pid))}">Add to cart</button>
              </div>
            </div>
          `;
        }).join('');
  
        document.querySelectorAll('.add-to-cart').forEach(button => {
          button.addEventListener('click', e => {
            const pid = e.target.dataset.pid;
            if (validateInteger(pid)) cart.addItem(pid);
          });
        });
      })
      .catch(error => console.error('Error fetching products:', error));
  
    // Fetch and render categories for side navigation
    fetch(`https://${ipaddr}:3000/api/categories`)
      .then(response => {
        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
        return response.json();
      })
      .then(categories => {
        const categoryContainer = document.getElementById('side-nav-list');
        if (!categoryContainer) return;
        categoryContainer.innerHTML = categories.map(category => {
          if (!validateInteger(category.catid)) return '';
          return `
            <a href="category.html?catid=${encodeURIComponent(category.catid)}">
              <li>${escapeHtml(category.name)}</li>
            </a>
          `;
        }).join('');
      })
      .catch(error => console.error('Error fetching categories:', error));
  
    // Event delegation for cart interactions
    document.addEventListener('click', e => {
      const pid = e.target.dataset.pid;
      if (!pid || !validateInteger(pid)) return;
  
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
  
    document.addEventListener('input', e => {
      if (e.target.classList.contains('quantity')) {
        const pid = e.target.dataset.pid;
        const quantity = e.target.value;
        if (validateInteger(pid) && validateInteger(quantity)) {
          cart.updateQuantity(pid, quantity);
        } else {
          e.target.value = cart.items.get(pid)?.quantity || 1; // Reset if invalid
        }
      }
    });
  
    // Initial render
    cart.render();
  });