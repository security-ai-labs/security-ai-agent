"""
Vulnerable JavaScript code with XSS
DO NOT USE IN PRODUCTION
"""

// VULNERABLE: innerHTML with user input
function displayUserName(name) {
    document.getElementById('username').innerHTML = name;
}

// VULNERABLE: dangerouslySetInnerHTML in React
function UserProfile({ userBio }) {
    return (
        <div dangerouslySetInnerHTML={{__html: userBio}} />
    );
}

// VULNERABLE: eval with user input
function executeUserCode(code) {
    eval(code);
}

// VULNERABLE: document.write
function renderMessage(msg) {
    document.write("<p>" + msg + "</p>");
}
