function processData(data) {
    let results = [];
    let i = 0;
    
    while (i < data.length) {
        let item = data[i];
        
        if (item.isValid && item.score > 50) {
            let processed = {
                id: item.id,
                value: item.score * 2.5,
                category: "high"
            };
            results.push(processed);
        }
        
        i = i + 1;
    }
    
    return results;
}

let testData = [
    { id: 1, score: 75, isValid: true },
    { id: 2, score: 30, isValid: true },
    { id: 3, score: 90, isValid: false }
];

let processed = processData(testData);

function validate(item) {
    return item != null && item.score >= 0;
}