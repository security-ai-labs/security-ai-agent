"""
Safe JavaScript code - using textContent instead of innerHTML
This should NOT be flagged as XSS vulnerable
"""

// SAFE: Using textContent instead of innerHTML
function displayUsernameSafe(username) {
    const container = document.getElementById('username');
    container.textContent = username;  // Safe - no HTML parsing
}

// SAFE: Using innerText
function displayMessageSafe(message) {
    const element = document.getElementById('message');
    element.innerText = message;  // Safe - no HTML parsing
}

// SAFE: Creating text node
function addCommentSafe(comment) {
    const container = document.getElementById('comments');
    const textNode = document.createTextNode(comment);
    container.appendChild(textNode);  // Safe
}

// SAFE: Using React with proper escaping
function UserProfile({ name, bio }) {
    return (
        <div>
            <h1>{name}</h1>
            <p>{bio}</p>
        </div>
    );
}

// SAFE: Setting value property
function setInputValue(value) {
    document.getElementById('input').value = value;  // Safe
}
