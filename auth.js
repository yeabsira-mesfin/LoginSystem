const jwt = require('jsonwebtoken');

// A secret key for signing JWT tokens.
const secretKey = process.env.secretKey || 'default';

// A Simulated user.

const users = [
    {id: 1, username: 'Alicia', password: 'AL20'},
    {id: 2, username: 'Arron', password: 'AR23'}
];

// A function to authenticate user and generate JWT token
const authUser = (username, password) => {
    // Find user by username and password
    const user = users.find(user => user.username === username && user.password === password);

    if(!user){
        return null;
    }

    // Generate JWT token user id as playload.
    const token = jwt.sign({id: user.id}, secretKey,{expiresIn: '1h'})
    return token;
}

// Then we need a function to verify a JWT token

const verifyToken = (token) => {
    try{
        const decoded = jwt.verify(token,secretKey);
        return decoded;
    } catch (error){
        return null;
    }
}

module.exports = {
    users,
    authUser,
    verifyToken
}