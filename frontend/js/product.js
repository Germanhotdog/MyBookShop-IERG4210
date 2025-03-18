// Escape HTML to prevent XSS
function escapeHtml(unsafe) {
    return String(unsafe)
      .replace(/&/g, "&")
      .replace(/</g, "<")
      .replace(/>/g, ">")
      .replace(/"/g, "\"")
      .replace(/'/g, "\'");
  }
  
  // Validate integer input (e.g., pid, quantity)
  function validateInteger(value) {
    const num = parseInt(value, 10);
    return !isNaN(num) && num >= 0 && String(num) === String(value);
  }
  
  document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, fetching product...');
    // Use domain for production; localhost for local testing
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
  
      addItem(pid, quantity = 1) {
        if (!validateInteger(pid)) {
          console.error('Invalid pid:', pid);
          return;
        }
        if (this.items.has(pid)) {
          const item = this.items.get(pid);
          item.setQuantity(item.quantity + parseInt(quantity, 10));
        } else {
          this.items.set(pid, new CartItem(pid, quantity));
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
        const fetchPromises = cartData
          .filter(data => validateInteger(data.pid) && validateInteger(data.quantity))
          .map(data => {
            const item = new CartItem(data.pid, data.quantity);
            this.items.set(data.pid, item);
            return this.fetchProductDetails(data.pid);
          });
        Promise.all(fetchPromises).then(() => this.render());
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
  
    // Get product pid from URL query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('pid');
    console.log('Product ID from URL:', productId);
    if (!validateInteger(productId)) {
      console.error('Invalid product ID');
      document.querySelector('.product-container').innerHTML = '<p>Invalid Product ID</p>';
      return;
    }
  
    fetch(`https://${ipaddr}:3000/api/product/${encodeURIComponent(productId)}`)
      .then(response => {
        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
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
              categoryLink = `<a href="./category.html?catid=${encodeURIComponent(product.catid)}">${escapeHtml('Chinese Books')}</a>`;
              break;
            case 2:
              categoryLink = `<a href="./category.html?catid=${encodeURIComponent(product.catid)}">${escapeHtml('English Books')}</a>`;
              break;
            case 3:
              categoryLink = `<a href="./category.html?catid=${encodeURIComponent(product.catid)}">${escapeHtml('Magazines')}</a>`;
              break;
            default:
              categoryLink = `<a href="#">${escapeHtml('Unknown Category')}</a>`;
          }
          hierarchicalNav.innerHTML = `
            <a href="./index.html">${escapeHtml('Home')}</a> > 
            ${categoryLink} > 
            ${escapeHtml(product.name)}
          `;
        }
  
        // Update product container
        const productContainer = document.querySelector('.product-container');
        if (productContainer) {
          productContainer.innerHTML = `
            <img src="https://${ipaddr}:3000${escapeHtml(product.image)}" alt="${escapeHtml(product.name)}">
            <div class="product-description">
              <h2>${escapeHtml(product.name)}</h2>
              <h5>Author: ${escapeHtml(product.author || 'Unknown')}<br>Publisher: ${escapeHtml(product.publisher || 'Unknown')}</h5>
              <p>${escapeHtml(product.description || 'No description available')}</p>
            </div>
            <div class="purchase">
              <h3>${escapeHtml(product.name)}</h3>
              Price: $${escapeHtml(String(product.price.toFixed(2)))}
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
              <button class="add-to-cart" data-pid="${escapeHtml(String(product.pid))}">Add to cart</button>
            </div>
          `;
          document.querySelector('.add-to-cart').addEventListener('click', () => {
            const quantity = parseInt(document.getElementById('quantity').value, 10);
            const pid = product.pid;
            if (validateInteger(quantity)) cart.addItem(pid, quantity);
          });
        }
      })
      .catch(error => {
        console.error('Error fetching product:', error);
        document.querySelector('.product-container').innerHTML = '<p>Product Not Found</p>';
      });
  
    // Event delegation for cart interactions
    const shoppingList = document.querySelector('.shopping-list');
    if (shoppingList) {
      shoppingList.addEventListener('click', e => {
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
  
      shoppingList.addEventListener('input', e => {
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
    }
  
    // Initial render
    cart.render();
  });