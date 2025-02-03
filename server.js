const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const MAX_TIME_DIFFERENCE = +process.env.MAX_TIME_DIFFERENCE || 5000;
const secretKey = 'my-secret';

const port = 7100;

const verifySignature = (secret, payload, signature) => {
    if (!secret || !payload || !signature) return false;
    const hmac = crypto.createHmac('sha256', secretKey);
    hmac.update(Buffer.from(payload, 'utf-8'));
    const generatedSignature = hmac.digest('hex');

    if (generatedSignature.length !== signature.length) {
        throw new Error('Invalid signature length');
    }

    return crypto.timingSafeEqual(Buffer.from(generatedSignature), Buffer.from(signature));
};

// Allows access from everywhere. (Only for testing purposes)
app.use(cors());

app.use(express.json());

app.post('/webhook', (req, res) => {
    const timestamp = req.headers['x-timestamp'];
    const signature = req.headers['x-signature'];
    const payloadWithTimestamp = `${timestamp}.${JSON.stringify(req.body)}`;

    const currentTimestamp = Math.floor(Date.now());
    if (Math.abs(currentTimestamp - timestamp) > MAX_TIME_DIFFERENCE) {
        return res.status(400).json({ error: 'Expired timestamp' });
    }

    const hasValidSignature = verifySignature(secretKey, payloadWithTimestamp, signature);

    if (!hasValidSignature) {
        return res.status(403).json({ error: 'Invalid signature' });
    }

    console.log(`Computed Signature: ${signature}`);
    console.log(`Received Signature: ${req.headers['x-signature']}`);
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});