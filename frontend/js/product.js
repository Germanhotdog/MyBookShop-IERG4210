document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, fetching product...');

    // Get product pid from URL query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('pid');
    console.log('Product ID from URL:', productId);

    fetch(`http://localhost:3000/api/product/${productId}`)
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
                        categoryLink = '<a href="./chinesebooks.html">Chinese Books</a>';
                        break;
                    case 2:
                        categoryLink = '<a href="./englishbooks.html">English Books</a>';
                        break;
                    case 3:
                        categoryLink = '<a href="./magazines.html">Magazines</a>';
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
                    <img src="http://localhost:3000${product.image}" alt="${product.name}">
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
                        <a href="/add-to-cart/${product.pid}"><button>Add to cart</button></a>
                    </div>
                `;
            }
        })
        .catch(error => console.error('Error fetching product:', error));
});