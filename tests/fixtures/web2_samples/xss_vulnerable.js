"""
Vulnerable Node.js/JavaScript code with XSS
DO NOT USE IN PRODUCTION
"""

// VULNERABLE: innerHTML with user input
function displayUserComment(comment) {
    const container = document.getElementById('comments');
    container.innerHTML = comment;  // XSS risk!
}

// VULNERABLE: dangerouslySetInnerHTML in React
function UserProfile({ userBio }) {
    return (
        <div dangerouslySetInnerHTML={{__html: userBio}} />
    );
}

// VULNERABLE: eval with user input
function executeUserCode(code) {
    eval(code);  // Code injection risk!
}

// VULNERABLE: document.write with concatenation
function displayWelcome(username) {
    document.write("<h1>Welcome " + username + "</h1>");
}
