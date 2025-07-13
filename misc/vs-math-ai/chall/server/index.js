import express, { json } from 'express';
import * as math from 'mathjs';

const app = express();
const port = 3000;

app.use(json());

app.post('/evaluate', (req, res) => {
    try {
        const { expression } = req.body;
        const rawResult = math.evaluate(expression);
        const formattedResult = math.format(rawResult);
        res.json({ result: formattedResult, rawResult: JSON.stringify(rawResult) });
    } catch (error) {
        console.error("Evaluation error:", error.message);
        res.status(400).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});