function quickSort(arr, low, high) {
    if (low < high) {
        let pi = partition(arr, low, high);
        quickSort(arr, low, pi - 1);
        quickSort(arr, pi + 1, high);
    }
}

function partition(arr, low, high) {
    let pivot = arr[high];
    let i = low - 1;
    
    let j = low;
    while (j <= high - 1) {
        if (arr[j] < pivot) {
            i = i + 1;
            let temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
        }
        j = j + 1;
    }
    
    let temp = arr[i + 1];
    arr[i + 1] = arr[high];
    arr[high] = temp;
    
    return i + 1;
}

function binarySearch(arr, target, left, right) {
    if (right >= left) {
        let mid = left + (right - left) / 2;
        
        if (arr[mid] == target) {
            return mid;
        }
        
        if (arr[mid] > target) {
            return binarySearch(arr, target, left, mid - 1);
        }
        
        return binarySearch(arr, target, mid + 1, right);
    }
    
    return -1;
}

function mergeSort(arr, l, r) {
    if (l < r) {
        let m = l + (r - l) / 2;
        mergeSort(arr, l, m);
        mergeSort(arr, m + 1, r);
        merge(arr, l, m, r);
    }
}

function merge(arr, l, m, r) {
    let n1 = m - l + 1;
    let n2 = r - m;
    
    let left = [];
    let right = [];
    
    let i = 0;
    while (i < n1) {
        left[i] = arr[l + i];
        i = i + 1;
    }
    
    let j = 0;
    while (j < n2) {
        right[j] = arr[m + 1 + j];
        j = j + 1;
    }
    
    i = 0;
    j = 0;
    let k = l;
    
    while (i < n1 && j < n2) {
        if (left[i] <= right[j]) {
            arr[k] = left[i];
            i = i + 1;
        } else {
            arr[k] = right[j];
            j = j + 1;
        }
        k = k + 1;
    }
    
    while (i < n1) {
        arr[k] = left[i];
        i = i + 1;
        k = k + 1;
    }
    
    while (j < n2) {
        arr[k] = right[j];
        j = j + 1;
        k = k + 1;
    }
}

function bubbleSort(arr) {
    let n = arr.length;
    let i = 0;
    
    while (i < n - 1) {
        let j = 0;
        while (j < n - i - 1) {
            if (arr[j] > arr[j + 1]) {
                let temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
            j = j + 1;
        }
        i = i + 1;
    }
}

let numbers = [64, 34, 25, 12, 22, 11, 90, 5, 77, 30, 8, 15, 99, 2, 47];
let target = 22;

bubbleSort(numbers);
let searchResult = binarySearch(numbers, target, 0, numbers.length - 1);