function add(a, b) {
    return a + b;
}

function fibonacci(n) {
    if (n <= 1) {
        return n;
    } else {
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}

let result = add(5, 3);
let fib10 = fibonacci(10);