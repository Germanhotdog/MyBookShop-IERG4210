document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, fetching products...');
    //fetch and render products to Frontend
    fetch('http://localhost:3000/api/magazines')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(products => {
            console.log('Products received:', products);
            const container = document.getElementById('flex-container');
            if (!container) {
                console.error('Container not found!');
                return;
            }
            container.innerHTML = products.map(product => `
                <div class="magazine">
                    <a href="/product/${product.pid}" >
                        <img src="http://localhost:3000${product.image}" alt="${product.name}">
                        <p>${product.name}</p>
                    </a>
                    <div class="PriceButton-container">
                        <p>$${product.price.toFixed(2)}</p>
                        <a href="/add-to-cart/${product.pid}"><button>Add to cart</button></a>
                    </div>
                </div>
            `).join('');
        })
        .catch(error => console.error('Error fetching products:', error));
    
    //fetch and render categories to Frontend
    fetch('http://localhost:3000/api/categories')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(categories => {
            console.log('Categories received:', categories);
            const categoryContainer = document.getElementById('side-nav-list');
            if (!categoryContainer) {
                console.error('Category container not found!');
                return;
            }
            categoryContainer.innerHTML = categories.map(category => `
                <a href="${category.name.toLowerCase().replace(/\s+/g, '')}.html">
                    <li>${category.name}</li>
                </a>
            `).join('');
        })
        .catch(error => console.error('Error fetching categories:', error));
});