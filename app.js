const { users, authUser, verifyToken} = require('./auth');

const user1 = users[0].username;
const password = users[0].password;

console.log(`You are attempting to authenticate "${user1}"`);
const authToken = authUser(user1,password);
if(authToken){
    console.log('Authentication successful!');
    console.log('Generated JWT token:', authToken);;

    // Verifying token...

    console.log('Verifying token...');
    const decodedToken = verifyToken(authToken);
    if(decodedToken){
        console.log('Token is valid');
        console.log('Decoded token', decodedToken);
    } else {
        console.log('Token is invalid of expired')
    }
}
else{
    console.log('Authentication failed. Invalid username or password.')
}
