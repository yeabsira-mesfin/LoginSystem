const jwt = require('jsonwebtoken');

// A secret key for signing JWT tokens.
const secretKey = 'Scholes';

// A Simulated user.

const users = [
    {id: 1, username: 'Paul', password: 'ps18'},
    {id: 2, username: 'Arron', password: 'al23'}
];

// A function to authenticate user and generate JWT token
const authUser = (username, password) => {
    // Find user by username and password
    const user = users.find(user => user.username === username && user.password === password);

    if(!user){
        return null;
    }

    // Generate JWT token user id as playload.

    
}