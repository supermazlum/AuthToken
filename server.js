import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
app.use(express.json());

const users = [];

// Token wird generiert
function generateToken(user) {
    return jwt.sign({ id: user.id, email: user.email }, process.env.TOKEN_SECRET, { expiresIn: '30m' });
}

// Token wird authentifiziert
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);

        req.user = user;
        next();
    });
}

// Route für Registrierung des benutzers
app.post('/signup', async (req, res) => {
    try {
        const { email, password } = req.body;

        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            return res.status(409).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { id: users.length + 1, email, password: hashedPassword };
        users.push(newUser);

        res.status(201).json({ message: 'User created' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Route Anmeldung Benutzer
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = users.find(user => user.email === email);
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const token = generateToken(user);
        res.status(200).json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// SAfe Route
app.get('/secure', authenticateToken, (req, res) => {
    res.status(200).json({ authenticated: true });
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});