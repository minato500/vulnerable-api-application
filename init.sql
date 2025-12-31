USE vulndb;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    is_admin BOOLEAN DEFAULT FALSE,
    credit_card VARCHAR(20),
    ssn VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2),
    secret_cost DECIMAL(10, 2),
    internal_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    quantity INT,
    total_price DECIMAL(10, 2),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role, is_admin, credit_card, ssn) VALUES
('admin', 'admin123', 'admin@vulnapi.com', 'admin', TRUE, '4111-1111-1111-1111', '123-45-6789'),
('john', 'password123', 'john@example.com', 'user', FALSE, '4222-2222-2222-2222', '234-56-7890'),
('jane', 'jane2023', 'jane@example.com', 'user', FALSE, '4333-3333-3333-3333', '345-67-8901'),
('bob', 'bob123', 'bob@example.com', 'manager', FALSE, '4444-4444-4444-4444', '456-78-9012'),
('alice', 'alice456', 'alice@example.com', 'user', FALSE, '4555-5555-5555-5555', '567-89-0123');

INSERT INTO products (name, description, price, secret_cost, internal_notes) VALUES
('Laptop Pro', 'High-end laptop for professionals', 1299.99, 650.00, 'Margin: 50% - Priority supplier: TechCorp'),
('Wireless Mouse', 'Ergonomic wireless mouse', 49.99, 15.00, 'Low stock alert threshold: 50 units'),
('USB-C Hub', 'Multi-port USB-C hub', 79.99, 25.00, 'New supplier contract pending'),
('Mechanical Keyboard', 'RGB mechanical keyboard', 149.99, 45.00, 'Discontinuing in Q2 2024'),
('Monitor 4K', '32-inch 4K monitor', 499.99, 200.00, 'Warehouse B - Shelf 12');

INSERT INTO orders (user_id, product_id, quantity, total_price, status) VALUES
(2, 1, 1, 1299.99, 'completed'),
(2, 2, 2, 99.98, 'pending'),
(3, 3, 1, 79.99, 'shipped'),
(4, 4, 1, 149.99, 'completed'),
(5, 5, 2, 999.98, 'pending');
